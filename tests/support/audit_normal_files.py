#!/usr/bin/env python3
"""Audit modern unspliced Normal files against the sibling OEM Kernel's XOR skips.
Usage: audit_normal_files.py PACKAGES EXTRACTED OUTPUT_JSON
Outputs exclusions explicitly; no production decoder or test is an oracle.
"""
import hashlib,json,pathlib,re,struct,sys,tarfile
from audit_kernel_files import decode,state_before,A,C,INV,MASK,sum32
root,extracted,output=map(pathlib.Path,sys.argv[1:]);rows=[];excluded=[];seen=set(); checked_packages=set()
manifest=json.loads(output.with_name('oem_kernel_files.json').read_text())
for kernel in manifest:
    source=kernel['sources'][0]; kr=(extracted/(kernel['envelope_sha256']+'.enc')).read_bytes()
    if kernel['payload_offset']==0x1200:key=kr[0x200:0x1200]
    else:
        state=state_before(kr[0x10200:0x10210])
        for _ in range(0x11000):state=((state-C)*INV)&MASK
        key=bytearray()
        for _ in range(0x1000):state=(A*state+C)&MASK;key.append(state>>16)
    kb=decode(kr[kernel['payload_offset']:kernel['payload_offset']+0x10000],key)
    assert hashlib.sha256(kb).hexdigest()==kernel['body_sha256']
    # Two same-register CMP.L immediates, both BEQ landing after the XOR.
    branches=[]
    for m in re.finditer(rb'\x7a([\x20-\x27])(.{4})\x47(.)\x7a\1(.{4})\x47(.)',kb,re.S):
        at=m.start(); target1=at+8+m[3][0];target2=at+16+m[5][0]
        if target1==target2 and b'\x01\xf0\x65' in kb[at+16:target1]:
            branches.append((at,list(struct.unpack('>I',m[2])+struct.unpack('>I',m[4])),kb[at:target1].hex()))
    for source in kernel['sources']:
        package=root/source['package']
        if package not in checked_packages:
            assert hashlib.sha256(package.read_bytes()).hexdigest()==package.name.split('.')[0],package
            checked_packages.add(package)
        with tarfile.open(root/source['package']) as archive:
            for member in archive.getmembers():
                if not member.isfile() or member.size<0x10240:continue
                raw=archive.extractfile(member).read()
                if b'File Type : Normal' not in raw[:512]:continue
                digest=hashlib.sha256(raw).hexdigest()
                if digest in seen:continue
                seen.add(digest)
                base=dict(envelope_sha256=digest,kernel_sha256=kernel['envelope_sha256'],
                    source=dict(package=source['package'],member=member.name))
                if len(branches)!=1:
                    excluded.append(dict(**base,reason='no unique audited two-compare XOR branch'));continue
                at,skips,instructions=branches[0];found=None
                for key_start in (0x200,0x10200):
                    payload=key_start+0x10000
                    if payload+64>len(raw) or (len(raw)-payload)%4:continue
                    words=struct.unpack('<16384I',raw[key_start:payload]); image=bytearray()
                    for i,(word,) in enumerate(struct.iter_unpack('<I',raw[payload:])):
                        k=words[i%16384];v=word^(0 if i*4 in skips else k);n=k&31
                        image.extend(struct.pack('<I',((v>>n)|(v<<((32-n)%32)))&0xffffffff))
                        if i==15 and not image.startswith(b'PIONEER '):break
                    if len(image)==len(raw)-payload and image.startswith(b'PIONEER ') and sum32(image)==0 and int.from_bytes(image[20:24],'big')==len(image):
                        found=(payload,image);break
                if found is None:
                    excluded.append(dict(**base,reason='not proven continuous standard rotation + OEM skip offsets + declared size + zero checksum'));continue
                payload,image=found
                (extracted/(digest+'.enc')).write_bytes(raw)
                rows.append(dict(**base,payload_offset=payload,body_sha256=hashlib.sha256(image).hexdigest(),
                    body_size=len(image),xor_offsets=skips,branch_offset=at,branch_bytes=instructions))

output.write_text(json.dumps(rows,indent=2)+'\n')
output.with_name('oem_normal_exclusions.json').write_text(json.dumps(excluded,indent=2)+'\n')
output.with_name('oem_normal_cases.rs.inc').write_text(''.join(f'case!(oem_normal_{r["envelope_sha256"][:16]}, {i});\n' for i,r in enumerate(rows)))
print(f'{len(rows)} independently validated Normal files; {len(excluded)} explicit exclusions')
