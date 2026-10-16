#!/usr/bin/env python3
"""Independent OEM Kernel file audit: Python integers, no pioneer-optical calls.
Usage: audit_kernel_files.py PACKAGES OUTPUT_JSON
Decoding uses the OEM XOR/rotate operation; see OEM_FACTS.md for evidence.
"""
import hashlib,json,pathlib,struct,sys,tarfile
MASK=(1<<24)-1; A=214013; C=2531011; INV=pow(A,-1,1<<24)
def state_before(sample):
    for low in range(65536):
        state=(sample[0]<<16)|low; initial=state
        for want in sample[1:]:
            state=(A*state+C)&MASK
            if state>>16 != want: break
        else: return ((initial-C)*INV)&MASK
    raise ValueError('no LCG state')
def decode(cipher,key):
    words=struct.unpack('<1024I',key); out=bytearray()
    for i,(v,) in enumerate(struct.iter_unpack('<I',cipher)):
        k=words[i%1024]; v^=k; r=k&31
        out.extend(struct.pack('<I',((v>>r)|(v<<((32-r)%32)))&0xffffffff))
    return bytes(out)
def sum32(b):return sum(w[0] for w in struct.iter_unpack('>I',b))&0xffffffff
def main():
    root=pathlib.Path(sys.argv[1]); rows={}
    for package in sorted(root.rglob('*.tar')):
        assert hashlib.sha256(package.read_bytes()).hexdigest() == package.name.split('.')[0], package
        with tarfile.open(package) as archive:
            for member in archive.getmembers():
                if not member.isfile() or member.size != 0x11200: continue
                raw=archive.extractfile(member).read()
                if b'File Type : Kernel' not in raw[:512]: continue
                digest=hashlib.sha256(raw).hexdigest()
                if digest in rows:
                    rows[digest]["sources"].append(dict(package=str(package.relative_to(root)),member=member.name))
                    continue
                key=raw[0x200:0x1200]; body=decode(raw[0x1200:],key); payload=0x1200
                if sum32(body)!=0 or b'SAT ' not in body[0x1000:0x1040]:
                    state=state_before(raw[0x10200:0x10210])
                    for _ in range(0x11000): state=((state-C)*INV)&MASK
                    key=bytearray()
                    for _ in range(0x1000):
                        state=(state*A+C)&MASK;key.append(state>>16)
                    body=decode(raw[0x200:0x10200],key);payload=0x200
                assert sum32(body)==0 and b'SAT ' in body[0x1000:0x1040],(package,member.name)
                fields={}
                for line in raw[:512].split(b'\r\n'):
                    if b' : ' in line:
                        k,v=line.split(b' : ',1);fields[k.decode('ascii')]=v.rstrip(b'\x00 ').decode('ascii')
                rows[digest]=dict(envelope_sha256=digest,body_sha256=hashlib.sha256(body).hexdigest(),
                    key_sha256=hashlib.sha256(key).hexdigest(),payload_offset=payload,fields=fields,
                    sources=[dict(package=str(package.relative_to(root)),member=member.name)])
    output=pathlib.Path(sys.argv[2]);values=list(rows.values())
    output.write_text(json.dumps(values,indent=2)+'\n')
    output.with_name('oem_kernel_files_cases.rs.inc').write_text(''.join(
        f'case!(oem_file_{r["envelope_sha256"][:16]}, {i});\n' for i,r in enumerate(values)))
    print(f'{len(values)} envelopes; {len(set(r["body_sha256"] for r in values))} bodies; '
          f'{sum(r["payload_offset"]==0x200 for r in values)} derived-key files')

if __name__ == "__main__":
    main()
