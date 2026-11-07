//! Complete bounded native role shapes; see docs/capacity-relation.md.
//! Normalization changes only explicit covered-role pointers; all other bytes
//! (including RAM/MMIO operands, loop bounds and branch opcodes) are exact.
use super::{Component, Form, Relocation, Span};
const ROLES_0: &[Span] = &[
    // normal-entry-vector
    Span {
        component: Component::Normal,
        start: 0x2000,
        len: 4,
        digest: [
            169, 98, 201, 154, 224, 102, 100, 21, 231, 142, 251, 150, 186, 177, 3, 159, 64, 74,
            190, 159, 155, 232, 142, 49, 126, 231, 228, 196, 115, 223, 170, 50,
        ],
        relocations: &[Relocation {
            at: 1,
            width: 3,
            role: 4,
            offset: 0,
        }],
    },
    // normal-copied-source_cpu
    Span {
        component: Component::Normal,
        start: 0x16b958,
        len: 652,
        digest: [
            193, 141, 81, 50, 244, 4, 93, 61, 234, 176, 1, 56, 53, 166, 47, 24, 202, 156, 156, 182,
            103, 121, 85, 215, 30, 33, 119, 19, 217, 48, 26, 179,
        ],
        relocations: &[],
    },
    // normal-copied-body_cpu
    Span {
        component: Component::Normal,
        start: 0x16bab6,
        len: 46,
        digest: [
            237, 239, 103, 242, 9, 172, 169, 191, 28, 13, 182, 171, 197, 200, 95, 63, 167, 122,
            254, 22, 133, 57, 44, 12, 48, 94, 234, 179, 179, 255, 102, 50,
        ],
        relocations: &[],
    },
    // normal-copied-copy_cpu
    Span {
        component: Component::Normal,
        start: 0x9eb98,
        len: 20,
        digest: [
            147, 146, 184, 243, 183, 153, 42, 175, 101, 166, 110, 43, 179, 57, 192, 170, 42, 80,
            220, 49, 26, 157, 103, 6, 237, 244, 246, 165, 199, 212, 132, 33,
        ],
        relocations: &[],
    },
    // normal-copied-initializer_cpu
    Span {
        component: Component::Normal,
        start: 0x9eb12,
        len: 272,
        digest: [
            212, 136, 239, 106, 36, 183, 70, 212, 71, 229, 195, 9, 57, 56, 100, 152, 161, 44, 125,
            146, 255, 58, 212, 200, 171, 109, 21, 201, 67, 143, 60, 125,
        ],
        relocations: &[
            Relocation {
                at: 155,
                width: 3,
                role: 128,
                offset: 0,
            },
            Relocation {
                at: 227,
                width: 3,
                role: 153,
                offset: 0,
            },
            Relocation {
                at: 247,
                width: 3,
                role: 15,
                offset: 0,
            },
            Relocation {
                at: 251,
                width: 3,
                role: 154,
                offset: 0,
            },
            Relocation {
                at: 255,
                width: 3,
                role: 132,
                offset: 0,
            },
            Relocation {
                at: 259,
                width: 3,
                role: 9,
                offset: 0,
            },
        ],
    },
    // normal-helpers_cpu/0
    Span {
        component: Component::Normal,
        start: 0x16896a,
        len: 24,
        digest: [
            22, 51, 165, 244, 48, 233, 184, 219, 9, 215, 36, 105, 153, 187, 19, 151, 148, 188, 44,
            7, 112, 154, 202, 220, 162, 51, 202, 186, 65, 2, 192, 168,
        ],
        relocations: &[Relocation {
            at: 15,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // normal-helpers_cpu/1
    Span {
        component: Component::Normal,
        start: 0x16c02c,
        len: 30,
        digest: [
            13, 47, 29, 81, 236, 247, 220, 65, 151, 235, 28, 205, 180, 85, 52, 88, 125, 246, 29,
            100, 137, 51, 97, 248, 98, 155, 36, 240, 94, 75, 191, 213,
        ],
        relocations: &[],
    },
    // normal-clear_helpers_cpu/0
    Span {
        component: Component::Normal,
        start: 0x168982,
        len: 18,
        digest: [
            47, 189, 110, 221, 49, 130, 252, 242, 163, 69, 58, 22, 192, 109, 126, 213, 218, 129,
            53, 85, 172, 28, 114, 122, 28, 191, 186, 210, 17, 111, 33, 224,
        ],
        relocations: &[Relocation {
            at: 11,
            width: 3,
            role: 8,
            offset: 0,
        }],
    },
    // normal-clear_helpers_cpu/1
    Span {
        component: Component::Normal,
        start: 0x16c04a,
        len: 50,
        digest: [
            102, 201, 134, 246, 216, 61, 57, 227, 82, 118, 113, 54, 142, 160, 0, 19, 196, 150, 1,
            109, 50, 173, 81, 11, 181, 240, 103, 188, 30, 255, 195, 161,
        ],
        relocations: &[],
    },
    // normal-root-dispatcher
    Span {
        component: Component::Normal,
        start: 0x13edc0,
        len: 32,
        digest: [
            27, 54, 218, 38, 200, 74, 129, 127, 122, 201, 50, 187, 213, 213, 12, 178, 62, 85, 170,
            240, 41, 112, 78, 98, 157, 105, 158, 253, 136, 132, 141, 178,
        ],
        relocations: &[
            Relocation {
                at: 1,
                width: 3,
                role: 166,
                offset: 0,
            },
            Relocation {
                at: 5,
                width: 3,
                role: 155,
                offset: 0,
            },
            Relocation {
                at: 29,
                width: 3,
                role: 170,
                offset: 1370,
            },
        ],
    },
    // normal-initial-data-source/0
    Span {
        component: Component::Normal,
        start: 0x1a2d3e,
        len: 168,
        digest: [
            62, 198, 236, 109, 139, 244, 83, 198, 226, 152, 206, 59, 101, 211, 213, 168, 249, 207,
            47, 221, 80, 81, 37, 145, 88, 185, 5, 60, 241, 82, 162, 196,
        ],
        relocations: &[],
    },
    // normal-initial-data-source/1
    Span {
        component: Component::Normal,
        start: 0x184dee,
        len: 1530,
        digest: [
            106, 14, 151, 211, 50, 193, 230, 221, 93, 134, 211, 103, 4, 137, 212, 16, 116, 45, 180,
            44, 154, 2, 124, 176, 209, 224, 153, 178, 241, 110, 175, 168,
        ],
        relocations: &[],
    },
    // normal-initial-data-source/2
    Span {
        component: Component::Normal,
        start: 0x1853e8,
        len: 16,
        digest: [
            233, 232, 158, 186, 165, 103, 147, 67, 224, 171, 59, 125, 121, 226, 218, 15, 26, 143,
            146, 45, 113, 190, 135, 55, 1, 192, 59, 216, 14, 38, 145, 46,
        ],
        relocations: &[],
    },
    // normal-initial-data-source/3
    Span {
        component: Component::Normal,
        start: 0x1ad088,
        len: 398,
        digest: [
            120, 191, 132, 154, 61, 76, 189, 34, 112, 167, 188, 120, 42, 184, 224, 212, 9, 114,
            150, 79, 151, 93, 155, 56, 183, 173, 101, 244, 66, 35, 171, 14,
        ],
        relocations: &[],
    },
    // constructor-table
    Span {
        component: Component::Normal,
        start: 0x1a2de6,
        len: 204,
        digest: [
            192, 199, 69, 67, 204, 157, 204, 127, 13, 220, 36, 234, 206, 216, 92, 39, 138, 163,
            227, 87, 211, 203, 49, 153, 119, 168, 20, 13, 38, 38, 141, 6,
        ],
        relocations: &[
            Relocation {
                at: 0,
                width: 4,
                role: 16,
                offset: 0,
            },
            Relocation {
                at: 4,
                width: 4,
                role: 17,
                offset: 0,
            },
            Relocation {
                at: 8,
                width: 4,
                role: 18,
                offset: 0,
            },
            Relocation {
                at: 12,
                width: 4,
                role: 24,
                offset: 0,
            },
            Relocation {
                at: 16,
                width: 4,
                role: 39,
                offset: 0,
            },
            Relocation {
                at: 20,
                width: 4,
                role: 40,
                offset: 0,
            },
            Relocation {
                at: 24,
                width: 4,
                role: 41,
                offset: 0,
            },
            Relocation {
                at: 28,
                width: 4,
                role: 52,
                offset: 0,
            },
            Relocation {
                at: 32,
                width: 4,
                role: 53,
                offset: 0,
            },
            Relocation {
                at: 36,
                width: 4,
                role: 54,
                offset: 0,
            },
            Relocation {
                at: 40,
                width: 4,
                role: 55,
                offset: 0,
            },
            Relocation {
                at: 44,
                width: 4,
                role: 56,
                offset: 0,
            },
            Relocation {
                at: 48,
                width: 4,
                role: 57,
                offset: 0,
            },
            Relocation {
                at: 52,
                width: 4,
                role: 58,
                offset: 0,
            },
            Relocation {
                at: 56,
                width: 4,
                role: 59,
                offset: 0,
            },
            Relocation {
                at: 60,
                width: 4,
                role: 63,
                offset: 0,
            },
            Relocation {
                at: 64,
                width: 4,
                role: 70,
                offset: 0,
            },
            Relocation {
                at: 68,
                width: 4,
                role: 71,
                offset: 0,
            },
            Relocation {
                at: 72,
                width: 4,
                role: 72,
                offset: 0,
            },
            Relocation {
                at: 76,
                width: 4,
                role: 73,
                offset: 0,
            },
            Relocation {
                at: 80,
                width: 4,
                role: 74,
                offset: 0,
            },
            Relocation {
                at: 84,
                width: 4,
                role: 75,
                offset: 0,
            },
            Relocation {
                at: 88,
                width: 4,
                role: 79,
                offset: 36,
            },
            Relocation {
                at: 92,
                width: 4,
                role: 81,
                offset: 0,
            },
            Relocation {
                at: 96,
                width: 4,
                role: 82,
                offset: 0,
            },
            Relocation {
                at: 100,
                width: 4,
                role: 84,
                offset: 0,
            },
            Relocation {
                at: 104,
                width: 4,
                role: 85,
                offset: 0,
            },
            Relocation {
                at: 108,
                width: 4,
                role: 87,
                offset: 0,
            },
            Relocation {
                at: 112,
                width: 4,
                role: 89,
                offset: 0,
            },
            Relocation {
                at: 116,
                width: 4,
                role: 91,
                offset: 0,
            },
            Relocation {
                at: 120,
                width: 4,
                role: 92,
                offset: 0,
            },
            Relocation {
                at: 124,
                width: 4,
                role: 93,
                offset: 0,
            },
            Relocation {
                at: 128,
                width: 4,
                role: 94,
                offset: 0,
            },
            Relocation {
                at: 132,
                width: 4,
                role: 95,
                offset: 0,
            },
            Relocation {
                at: 136,
                width: 4,
                role: 96,
                offset: 0,
            },
            Relocation {
                at: 140,
                width: 4,
                role: 98,
                offset: 0,
            },
            Relocation {
                at: 144,
                width: 4,
                role: 99,
                offset: 0,
            },
            Relocation {
                at: 148,
                width: 4,
                role: 102,
                offset: 0,
            },
            Relocation {
                at: 152,
                width: 4,
                role: 103,
                offset: 0,
            },
            Relocation {
                at: 156,
                width: 4,
                role: 104,
                offset: 0,
            },
            Relocation {
                at: 160,
                width: 4,
                role: 105,
                offset: 0,
            },
            Relocation {
                at: 164,
                width: 4,
                role: 108,
                offset: 0,
            },
            Relocation {
                at: 168,
                width: 4,
                role: 109,
                offset: 0,
            },
            Relocation {
                at: 172,
                width: 4,
                role: 110,
                offset: 0,
            },
            Relocation {
                at: 176,
                width: 4,
                role: 111,
                offset: 0,
            },
            Relocation {
                at: 180,
                width: 4,
                role: 113,
                offset: 0,
            },
            Relocation {
                at: 184,
                width: 4,
                role: 114,
                offset: 0,
            },
            Relocation {
                at: 188,
                width: 4,
                role: 115,
                offset: 0,
            },
            Relocation {
                at: 192,
                width: 4,
                role: 116,
                offset: 0,
            },
            Relocation {
                at: 196,
                width: 4,
                role: 117,
                offset: 0,
            },
            Relocation {
                at: 200,
                width: 4,
                role: 118,
                offset: 0,
            },
        ],
    },
    // constructor-dispatcher
    Span {
        component: Component::Normal,
        start: 0x16bda6,
        len: 34,
        digest: [
            117, 70, 54, 1, 246, 71, 92, 179, 145, 127, 143, 153, 6, 164, 226, 247, 65, 202, 41,
            230, 179, 38, 61, 81, 129, 15, 9, 29, 46, 145, 117, 124,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x4648,
        len: 10,
        digest: [
            239, 3, 17, 106, 169, 150, 79, 62, 170, 86, 68, 5, 95, 172, 50, 170, 115, 189, 36, 187,
            184, 13, 160, 133, 59, 218, 24, 26, 184, 38, 62, 157,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x4b80,
        len: 22,
        digest: [
            26, 234, 184, 181, 33, 233, 15, 25, 59, 180, 39, 187, 40, 104, 64, 255, 126, 112, 135,
            214, 85, 45, 220, 129, 200, 85, 92, 229, 51, 11, 54, 140,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 119,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 119,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x4de4,
        len: 40,
        digest: [
            226, 103, 173, 196, 126, 227, 48, 121, 214, 56, 244, 154, 123, 248, 142, 32, 186, 35,
            103, 157, 238, 25, 241, 143, 203, 52, 101, 243, 71, 121, 7, 121,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 22,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 19,
                offset: 0,
            },
            Relocation {
                at: 27,
                width: 3,
                role: 21,
                offset: 0,
            },
            Relocation {
                at: 37,
                width: 3,
                role: 19,
                offset: 0,
            },
        ],
    },
    // constructor/part1
    Span {
        component: Component::Normal,
        start: 0x16bdda,
        len: 46,
        digest: [
            186, 205, 117, 177, 129, 255, 219, 143, 224, 108, 91, 109, 145, 122, 177, 196, 9, 252,
            112, 220, 109, 150, 221, 92, 38, 44, 22, 154, 23, 191, 197, 9,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x53e2,
        len: 36,
        digest: [
            197, 102, 174, 49, 97, 204, 110, 76, 232, 76, 79, 161, 13, 246, 210, 237, 13, 247, 24,
            13, 206, 197, 219, 70, 230, 246, 69, 17, 225, 130, 250, 114,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x544a,
        len: 44,
        digest: [
            143, 47, 185, 209, 255, 78, 170, 107, 168, 150, 86, 30, 201, 187, 217, 142, 244, 74,
            206, 202, 83, 199, 165, 107, 255, 209, 44, 188, 54, 17, 37, 32,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 20,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x5520,
        len: 44,
        digest: [
            184, 53, 53, 159, 94, 99, 136, 141, 70, 61, 134, 82, 83, 29, 112, 18, 18, 225, 206,
            207, 243, 50, 173, 161, 10, 153, 81, 249, 50, 112, 151, 242,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 20,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x574a,
        len: 30,
        digest: [
            179, 99, 240, 10, 171, 209, 189, 203, 154, 253, 156, 136, 155, 21, 183, 95, 144, 242,
            21, 163, 10, 36, 86, 230, 236, 172, 183, 171, 55, 98, 68, 195,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x59b2,
        len: 142,
        digest: [
            194, 11, 15, 41, 105, 76, 109, 127, 161, 15, 42, 154, 192, 140, 216, 34, 53, 229, 10,
            228, 23, 217, 253, 77, 224, 62, 169, 233, 183, 200, 157, 234,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 32,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 31,
                offset: 0,
            },
            Relocation {
                at: 27,
                width: 3,
                role: 34,
                offset: 0,
            },
            Relocation {
                at: 37,
                width: 3,
                role: 36,
                offset: 0,
            },
            Relocation {
                at: 47,
                width: 3,
                role: 29,
                offset: 0,
            },
            Relocation {
                at: 57,
                width: 3,
                role: 37,
                offset: 0,
            },
            Relocation {
                at: 67,
                width: 3,
                role: 30,
                offset: 0,
            },
            Relocation {
                at: 77,
                width: 3,
                role: 35,
                offset: 0,
            },
            Relocation {
                at: 87,
                width: 3,
                role: 25,
                offset: 0,
            },
            Relocation {
                at: 97,
                width: 3,
                role: 26,
                offset: 0,
            },
            Relocation {
                at: 107,
                width: 3,
                role: 33,
                offset: 0,
            },
            Relocation {
                at: 117,
                width: 3,
                role: 27,
                offset: 0,
            },
            Relocation {
                at: 127,
                width: 3,
                role: 28,
                offset: 0,
            },
            Relocation {
                at: 137,
                width: 3,
                role: 38,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x6882,
        len: 44,
        digest: [
            17, 76, 67, 18, 95, 13, 19, 27, 164, 152, 150, 180, 155, 6, 71, 188, 139, 35, 153, 233,
            135, 148, 123, 147, 206, 113, 99, 89, 103, 175, 246, 203,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x6f48,
        len: 44,
        digest: [
            89, 87, 139, 228, 61, 89, 86, 95, 140, 243, 57, 128, 91, 178, 244, 145, 14, 236, 237,
            246, 127, 25, 0, 208, 129, 185, 239, 210, 212, 88, 137, 121,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x7066,
        len: 44,
        digest: [
            38, 66, 252, 201, 113, 143, 29, 112, 33, 41, 133, 235, 232, 229, 253, 109, 136, 117,
            49, 16, 11, 118, 255, 21, 193, 88, 56, 135, 100, 78, 64, 195,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x70da,
        len: 44,
        digest: [
            239, 53, 209, 128, 118, 108, 139, 78, 153, 244, 43, 72, 252, 4, 42, 69, 179, 120, 211,
            128, 31, 165, 254, 177, 72, 182, 60, 172, 137, 79, 130, 115,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x747c,
        len: 44,
        digest: [
            27, 16, 251, 172, 95, 199, 176, 205, 111, 102, 189, 147, 29, 18, 124, 212, 221, 201,
            244, 216, 90, 15, 59, 36, 195, 190, 174, 153, 205, 47, 14, 248,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x750a,
        len: 44,
        digest: [
            58, 131, 103, 204, 96, 139, 203, 225, 253, 61, 254, 161, 64, 187, 123, 227, 41, 231, 4,
            159, 5, 242, 104, 227, 31, 231, 35, 96, 40, 49, 133, 228,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x7572,
        len: 44,
        digest: [
            196, 222, 128, 37, 46, 187, 26, 85, 124, 28, 97, 176, 40, 31, 205, 34, 161, 224, 118,
            170, 183, 219, 153, 225, 240, 14, 93, 244, 72, 133, 128, 210,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x75ac,
        len: 50,
        digest: [
            128, 39, 85, 147, 32, 174, 197, 128, 77, 14, 239, 245, 103, 226, 80, 229, 210, 91, 205,
            106, 79, 95, 146, 109, 171, 153, 161, 160, 212, 241, 156, 79,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x766a,
        len: 44,
        digest: [
            125, 219, 227, 45, 138, 140, 244, 223, 215, 253, 7, 224, 220, 71, 104, 149, 177, 32,
            201, 49, 131, 67, 215, 134, 226, 4, 138, 137, 94, 154, 37, 245,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x76de,
        len: 44,
        digest: [
            215, 133, 105, 144, 69, 18, 221, 73, 204, 140, 15, 186, 101, 61, 137, 215, 24, 104, 75,
            85, 84, 172, 64, 229, 252, 168, 9, 52, 63, 234, 32, 26,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x7866,
        len: 44,
        digest: [
            207, 191, 203, 7, 199, 15, 135, 226, 92, 151, 144, 121, 5, 26, 15, 109, 100, 112, 254,
            104, 4, 62, 116, 184, 19, 196, 61, 149, 51, 170, 220, 148,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x7990,
        len: 44,
        digest: [
            232, 155, 121, 209, 107, 226, 10, 96, 148, 48, 23, 32, 46, 197, 211, 71, 222, 212, 221,
            128, 178, 149, 197, 108, 85, 34, 167, 208, 69, 78, 27, 225,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x7a1e,
        len: 44,
        digest: [
            14, 147, 92, 181, 62, 159, 38, 121, 116, 78, 146, 240, 31, 95, 68, 5, 29, 80, 4, 75,
            80, 118, 164, 190, 217, 35, 163, 27, 158, 102, 195, 221,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x7a86,
        len: 44,
        digest: [
            142, 128, 88, 166, 27, 134, 205, 17, 106, 37, 213, 227, 42, 163, 132, 94, 204, 126,
            124, 114, 26, 37, 189, 194, 253, 170, 82, 38, 54, 197, 233, 25,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13c0c,
        len: 12,
        digest: [
            85, 17, 92, 41, 247, 253, 106, 196, 93, 216, 118, 8, 195, 119, 117, 226, 39, 219, 237,
            103, 230, 206, 191, 139, 161, 163, 92, 26, 226, 219, 133, 167,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 112,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x1f296,
        len: 40,
        digest: [
            194, 135, 12, 248, 247, 5, 18, 217, 53, 108, 172, 245, 38, 111, 204, 139, 64, 62, 233,
            97, 185, 236, 82, 131, 235, 166, 200, 170, 96, 254, 171, 102,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x2f5ec,
        len: 996,
        digest: [
            8, 144, 194, 137, 165, 158, 238, 130, 187, 70, 158, 157, 223, 40, 53, 89, 85, 122, 152,
            239, 23, 26, 113, 244, 173, 248, 61, 166, 95, 181, 167, 213,
        ],
        relocations: &[
            Relocation {
                at: 335,
                width: 3,
                role: 42,
                offset: 0,
            },
            Relocation {
                at: 645,
                width: 3,
                role: 43,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x30330,
        len: 40,
        digest: [
            90, 241, 5, 201, 74, 80, 176, 183, 52, 238, 108, 57, 89, 82, 178, 230, 184, 230, 165,
            181, 113, 217, 250, 135, 35, 106, 79, 34, 193, 240, 223, 216,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x3a5a0,
        len: 34,
        digest: [
            113, 111, 58, 217, 236, 211, 225, 190, 79, 26, 63, 232, 246, 24, 0, 111, 156, 85, 57,
            165, 240, 132, 159, 134, 12, 192, 231, 187, 205, 99, 128, 7,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x3feda,
        len: 58,
        digest: [
            8, 210, 73, 123, 228, 86, 208, 171, 201, 22, 143, 102, 17, 244, 30, 201, 139, 127, 150,
            50, 51, 131, 183, 160, 136, 18, 124, 98, 243, 240, 244, 150,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x3ffde,
        len: 58,
        digest: [
            208, 22, 141, 181, 118, 173, 136, 65, 122, 253, 12, 231, 89, 23, 88, 140, 20, 40, 247,
            235, 61, 36, 84, 56, 56, 109, 217, 12, 62, 8, 133, 210,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x4021a,
        len: 58,
        digest: [
            83, 173, 107, 55, 77, 221, 247, 117, 70, 111, 107, 112, 177, 125, 75, 89, 136, 48, 25,
            243, 171, 49, 81, 44, 14, 139, 221, 136, 22, 35, 103, 63,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x40316,
        len: 58,
        digest: [
            229, 130, 254, 77, 141, 153, 165, 234, 68, 112, 170, 47, 176, 43, 40, 102, 187, 119,
            158, 172, 18, 27, 113, 82, 87, 161, 236, 12, 1, 83, 242, 189,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x40452,
        len: 58,
        digest: [
            189, 217, 34, 86, 54, 123, 176, 149, 185, 14, 19, 15, 35, 175, 180, 28, 46, 184, 218,
            103, 171, 227, 253, 214, 121, 130, 14, 61, 65, 32, 30, 211,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x405b6,
        len: 58,
        digest: [
            225, 215, 89, 135, 92, 8, 191, 99, 98, 132, 84, 113, 245, 116, 40, 107, 14, 151, 246,
            106, 94, 29, 116, 182, 61, 214, 46, 81, 140, 57, 171, 150,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x406c2,
        len: 58,
        digest: [
            48, 69, 227, 156, 36, 231, 171, 125, 53, 104, 90, 104, 18, 163, 79, 229, 144, 217, 232,
            30, 173, 222, 86, 46, 94, 136, 161, 152, 202, 214, 47, 170,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x40834,
        len: 30,
        digest: [
            213, 28, 183, 118, 224, 72, 94, 84, 244, 21, 87, 17, 88, 216, 74, 247, 159, 215, 148,
            120, 191, 11, 236, 153, 185, 124, 128, 176, 15, 225, 52, 237,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x40e4a,
        len: 82,
        digest: [
            2, 48, 200, 83, 152, 48, 136, 254, 240, 95, 220, 167, 117, 219, 83, 97, 244, 195, 205,
            106, 160, 131, 217, 148, 174, 120, 37, 221, 244, 28, 186, 81,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 44,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 45,
                offset: 0,
            },
            Relocation {
                at: 27,
                width: 3,
                role: 46,
                offset: 0,
            },
            Relocation {
                at: 37,
                width: 3,
                role: 47,
                offset: 0,
            },
            Relocation {
                at: 47,
                width: 3,
                role: 48,
                offset: 0,
            },
            Relocation {
                at: 57,
                width: 3,
                role: 49,
                offset: 0,
            },
            Relocation {
                at: 67,
                width: 3,
                role: 50,
                offset: 0,
            },
            Relocation {
                at: 77,
                width: 3,
                role: 51,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x45310,
        len: 156,
        digest: [
            18, 214, 231, 220, 159, 27, 123, 172, 243, 78, 2, 71, 184, 173, 88, 136, 20, 200, 53,
            169, 4, 67, 138, 38, 66, 153, 134, 110, 186, 0, 203, 62,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x4fe80,
        len: 40,
        digest: [
            235, 144, 4, 196, 219, 205, 186, 43, 119, 86, 53, 141, 253, 178, 36, 104, 227, 252,
            206, 198, 204, 203, 106, 35, 109, 62, 58, 186, 211, 105, 6, 67,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x6a982,
        len: 22,
        digest: [
            50, 34, 71, 146, 44, 139, 144, 111, 94, 129, 177, 4, 250, 87, 32, 92, 143, 127, 250,
            240, 47, 94, 110, 2, 132, 33, 112, 98, 44, 37, 0, 86,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 112,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 112,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x8aa22,
        len: 12,
        digest: [
            46, 206, 48, 38, 187, 242, 63, 38, 176, 206, 144, 27, 171, 38, 225, 134, 114, 130, 29,
            247, 192, 43, 133, 3, 155, 141, 244, 27, 98, 61, 157, 203,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 112,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x99298,
        len: 30,
        digest: [
            201, 139, 157, 37, 229, 93, 176, 102, 129, 63, 197, 76, 195, 129, 210, 53, 153, 146,
            156, 230, 9, 7, 63, 233, 3, 35, 80, 51, 47, 187, 144, 224,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x99bb4,
        len: 30,
        digest: [
            60, 246, 48, 189, 186, 103, 130, 145, 212, 41, 111, 151, 133, 45, 227, 125, 88, 10,
            158, 194, 175, 130, 124, 63, 144, 0, 89, 102, 163, 165, 157, 234,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9c348,
        len: 44,
        digest: [
            11, 232, 225, 5, 52, 218, 159, 149, 91, 137, 12, 25, 43, 22, 86, 36, 18, 219, 112, 33,
            13, 151, 175, 156, 235, 7, 181, 131, 250, 43, 182, 40,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9c4ac,
        len: 46,
        digest: [
            49, 177, 122, 130, 41, 61, 24, 249, 214, 194, 91, 105, 242, 160, 104, 236, 188, 39, 72,
            38, 197, 25, 48, 146, 184, 191, 237, 248, 82, 20, 128, 81,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 61,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9c5e2,
        len: 44,
        digest: [
            10, 163, 251, 54, 93, 22, 175, 95, 161, 94, 161, 220, 196, 59, 33, 3, 40, 129, 142,
            164, 133, 96, 110, 200, 88, 223, 210, 107, 51, 178, 52, 204,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9c91a,
        len: 30,
        digest: [
            203, 101, 176, 19, 54, 80, 234, 131, 199, 27, 138, 184, 212, 60, 93, 191, 40, 101, 102,
            187, 74, 5, 48, 69, 208, 36, 219, 199, 0, 102, 105, 247,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9d17c,
        len: 96,
        digest: [
            158, 52, 40, 19, 87, 0, 71, 196, 244, 74, 177, 62, 187, 71, 170, 111, 166, 25, 248,
            238, 193, 194, 108, 184, 74, 24, 40, 113, 111, 51, 25, 60,
        ],
        relocations: &[
            Relocation {
                at: 11,
                width: 3,
                role: 66,
                offset: 0,
            },
            Relocation {
                at: 37,
                width: 3,
                role: 69,
                offset: 0,
            },
            Relocation {
                at: 61,
                width: 3,
                role: 68,
                offset: 0,
            },
            Relocation {
                at: 79,
                width: 3,
                role: 60,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9d1de,
        len: 44,
        digest: [
            215, 38, 233, 85, 115, 99, 150, 66, 223, 69, 142, 76, 83, 94, 162, 224, 196, 72, 159,
            46, 72, 159, 43, 4, 163, 62, 248, 3, 125, 66, 249, 47,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 67,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9d210,
        len: 44,
        digest: [
            85, 47, 254, 210, 49, 91, 193, 0, 156, 4, 211, 47, 235, 41, 245, 181, 80, 28, 149, 47,
            60, 252, 240, 242, 134, 119, 237, 159, 145, 80, 30, 9,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 67,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9d278,
        len: 44,
        digest: [
            167, 93, 157, 189, 80, 31, 88, 4, 135, 100, 85, 71, 215, 39, 135, 104, 131, 176, 26,
            125, 49, 115, 191, 96, 117, 3, 58, 18, 237, 207, 196, 116,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 62,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9d612,
        len: 76,
        digest: [
            24, 84, 109, 5, 211, 29, 178, 135, 118, 238, 126, 87, 146, 246, 188, 49, 184, 47, 157,
            222, 100, 236, 251, 85, 176, 173, 113, 175, 3, 190, 100, 172,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 62,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9dc04,
        len: 52,
        digest: [
            234, 14, 8, 96, 90, 77, 206, 65, 121, 241, 88, 45, 36, 6, 56, 71, 160, 213, 88, 28,
            112, 57, 214, 148, 48, 186, 99, 84, 208, 56, 216, 13,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 61,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9df66,
        len: 46,
        digest: [
            122, 185, 118, 204, 223, 95, 3, 183, 69, 142, 29, 181, 74, 124, 94, 63, 2, 247, 151,
            67, 104, 133, 207, 115, 238, 183, 160, 49, 135, 186, 3, 244,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 61,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xa12ce,
        len: 22,
        digest: [
            181, 217, 70, 163, 195, 186, 247, 191, 120, 80, 169, 236, 31, 115, 196, 255, 188, 40,
            170, 77, 3, 248, 119, 61, 195, 14, 76, 51, 222, 195, 244, 21,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 112,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 112,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xa620a,
        len: 30,
        digest: [
            172, 15, 1, 232, 211, 216, 74, 168, 10, 43, 102, 125, 95, 254, 1, 104, 123, 180, 30,
            146, 52, 187, 69, 36, 86, 58, 71, 247, 126, 30, 98, 45,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xa7c88,
        len: 18,
        digest: [
            217, 93, 63, 28, 51, 151, 113, 177, 244, 92, 252, 146, 104, 91, 70, 68, 56, 97, 12,
            185, 126, 157, 54, 155, 69, 14, 182, 19, 138, 29, 40, 142,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xa89c2,
        len: 124,
        digest: [
            53, 187, 178, 125, 45, 66, 132, 114, 227, 37, 154, 105, 213, 70, 50, 67, 32, 9, 234,
            137, 88, 193, 110, 53, 72, 99, 29, 192, 190, 144, 54, 23,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbc31a,
        len: 12,
        digest: [
            186, 222, 97, 156, 165, 243, 1, 102, 74, 134, 17, 108, 98, 166, 63, 153, 138, 204, 133,
            30, 151, 144, 239, 103, 202, 153, 239, 90, 81, 117, 75, 212,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 80,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbc36a,
        len: 12,
        digest: [
            84, 181, 154, 74, 184, 92, 92, 1, 208, 96, 185, 105, 169, 10, 242, 239, 40, 15, 133,
            135, 179, 125, 166, 68, 35, 187, 175, 216, 88, 128, 197, 15,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 78,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbcbde,
        len: 104,
        digest: [
            98, 148, 0, 56, 70, 193, 187, 131, 9, 241, 90, 119, 229, 1, 156, 210, 181, 98, 111,
            145, 198, 13, 15, 226, 243, 215, 204, 187, 253, 78, 11, 121,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbcc76,
        len: 16,
        digest: [
            183, 217, 24, 45, 223, 164, 211, 160, 62, 79, 6, 113, 196, 227, 183, 137, 244, 36, 119,
            78, 154, 3, 206, 83, 117, 48, 130, 71, 46, 204, 192, 150,
        ],
        relocations: &[Relocation {
            at: 11,
            width: 3,
            role: 76,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbcd10,
        len: 36,
        digest: [
            113, 67, 155, 54, 150, 62, 67, 171, 150, 13, 33, 118, 27, 111, 132, 224, 24, 153, 49,
            163, 246, 228, 7, 99, 130, 244, 66, 49, 206, 173, 4, 5,
        ],
        relocations: &[Relocation {
            at: 25,
            width: 3,
            role: 77,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbcd10,
        len: 44,
        digest: [
            225, 62, 140, 37, 234, 99, 120, 83, 157, 52, 202, 159, 209, 204, 149, 104, 132, 126,
            165, 102, 82, 210, 181, 190, 92, 158, 193, 239, 114, 210, 241, 69,
        ],
        relocations: &[Relocation {
            at: 25,
            width: 3,
            role: 77,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbd42c,
        len: 62,
        digest: [
            111, 188, 12, 233, 3, 57, 208, 172, 157, 145, 17, 229, 106, 161, 38, 104, 80, 141, 133,
            164, 224, 245, 218, 66, 115, 148, 67, 43, 136, 69, 162, 35,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xc9eb4,
        len: 22,
        digest: [
            148, 164, 169, 186, 246, 250, 65, 180, 99, 28, 224, 160, 49, 116, 77, 160, 106, 9, 1,
            231, 186, 25, 14, 189, 104, 168, 42, 49, 96, 21, 68, 9,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 112,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 112,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xd8470,
        len: 10,
        digest: [
            239, 238, 24, 137, 79, 187, 11, 147, 255, 147, 228, 119, 108, 255, 52, 44, 37, 16, 195,
            145, 121, 47, 188, 219, 155, 240, 41, 6, 74, 63, 95, 253,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xea834,
        len: 60,
        digest: [
            86, 114, 219, 232, 36, 90, 63, 123, 118, 3, 36, 207, 131, 242, 188, 179, 116, 211, 231,
            44, 127, 46, 157, 153, 51, 219, 1, 133, 11, 199, 223, 115,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xeba1e,
        len: 24,
        digest: [
            83, 178, 61, 216, 94, 130, 53, 151, 130, 129, 137, 81, 56, 250, 166, 184, 50, 112, 97,
            70, 104, 125, 99, 43, 100, 118, 58, 5, 49, 221, 181, 7,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 83,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xef016,
        len: 22,
        digest: [
            118, 203, 73, 159, 181, 204, 81, 220, 175, 66, 26, 209, 34, 122, 144, 185, 240, 254, 2,
            136, 247, 243, 90, 30, 90, 188, 120, 231, 241, 201, 1, 172,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xfa8fc,
        len: 88,
        digest: [
            95, 44, 42, 26, 189, 242, 97, 8, 179, 227, 131, 41, 38, 37, 15, 117, 173, 249, 124, 34,
            171, 216, 224, 68, 136, 203, 95, 86, 186, 96, 214, 155,
        ],
        relocations: &[
            Relocation {
                at: 29,
                width: 3,
                role: 121,
                offset: 0,
            },
            Relocation {
                at: 41,
                width: 3,
                role: 121,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xfb122,
        len: 36,
        digest: [
            193, 32, 131, 48, 166, 84, 124, 31, 83, 76, 137, 191, 151, 218, 221, 148, 196, 82, 218,
            216, 252, 47, 82, 141, 37, 98, 40, 95, 13, 136, 84, 47,
        ],
        relocations: &[Relocation {
            at: 29,
            width: 3,
            role: 123,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xfbaf4,
        len: 38,
        digest: [
            104, 202, 57, 70, 50, 214, 145, 76, 2, 141, 55, 62, 94, 151, 244, 142, 6, 222, 0, 43,
            167, 133, 111, 219, 9, 185, 140, 192, 130, 253, 51, 138,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 86,
                offset: 0,
            },
            Relocation {
                at: 27,
                width: 3,
                role: 8,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xfcb2a,
        len: 22,
        digest: [
            60, 255, 104, 163, 242, 185, 122, 111, 137, 203, 19, 21, 34, 116, 98, 92, 105, 215, 59,
            60, 26, 51, 251, 99, 172, 187, 45, 205, 2, 118, 202, 195,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 112,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 112,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x102422,
        len: 36,
        digest: [
            127, 209, 78, 93, 38, 44, 190, 80, 166, 193, 118, 132, 95, 153, 240, 19, 101, 156, 130,
            246, 144, 29, 178, 37, 227, 103, 148, 49, 32, 214, 176, 60,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x106b80,
        len: 492,
        digest: [
            50, 87, 59, 199, 192, 68, 105, 141, 21, 114, 39, 197, 172, 74, 117, 207, 29, 156, 210,
            129, 52, 10, 73, 242, 117, 113, 54, 235, 78, 51, 252, 247,
        ],
        relocations: &[
            Relocation {
                at: 319,
                width: 3,
                role: 112,
                offset: 0,
            },
            Relocation {
                at: 427,
                width: 3,
                role: 90,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x10ace2,
        len: 12,
        digest: [
            161, 201, 250, 108, 113, 221, 190, 17, 251, 145, 0, 149, 153, 35, 85, 172, 66, 203,
            236, 131, 143, 47, 56, 231, 61, 68, 211, 37, 58, 44, 101, 178,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 112,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x111000,
        len: 10,
        digest: [
            178, 65, 241, 217, 17, 131, 229, 85, 177, 132, 134, 10, 189, 50, 38, 5, 195, 5, 1, 211,
            230, 36, 86, 223, 188, 46, 80, 155, 69, 241, 209, 7,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x111650,
        len: 10,
        digest: [
            220, 10, 73, 30, 131, 19, 51, 72, 201, 96, 81, 10, 168, 188, 204, 34, 16, 176, 194, 47,
            146, 61, 157, 77, 83, 99, 135, 201, 5, 233, 98, 119,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x11564e,
        len: 10,
        digest: [
            194, 84, 207, 194, 35, 202, 51, 73, 135, 47, 191, 88, 31, 196, 239, 128, 18, 253, 4,
            193, 18, 127, 120, 252, 37, 58, 141, 140, 246, 8, 57, 143,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x116a5e,
        len: 10,
        digest: [
            203, 103, 197, 251, 244, 221, 25, 255, 39, 78, 226, 241, 50, 82, 66, 115, 55, 10, 12,
            244, 14, 1, 152, 132, 108, 12, 172, 177, 20, 172, 226, 110,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x1198ee,
        len: 32,
        digest: [
            51, 50, 217, 40, 189, 1, 110, 33, 98, 7, 109, 56, 13, 53, 118, 81, 165, 99, 38, 82,
            245, 93, 73, 69, 229, 128, 105, 125, 186, 149, 156, 39,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x11b496,
        len: 30,
        digest: [
            200, 111, 243, 163, 169, 178, 76, 145, 253, 46, 208, 78, 204, 11, 232, 245, 36, 25,
            132, 112, 11, 55, 164, 27, 176, 46, 40, 29, 168, 71, 145, 206,
        ],
        relocations: &[Relocation {
            at: 25,
            width: 3,
            role: 97,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x11fb96,
        len: 12,
        digest: [
            232, 125, 253, 236, 127, 23, 57, 74, 202, 18, 140, 94, 108, 16, 225, 183, 225, 210,
            179, 130, 192, 39, 137, 71, 36, 22, 220, 117, 36, 109, 49, 1,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 119,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x12038a,
        len: 36,
        digest: [
            153, 29, 205, 22, 201, 97, 35, 212, 227, 156, 84, 234, 237, 73, 15, 136, 40, 80, 101,
            203, 13, 237, 85, 8, 41, 51, 33, 234, 174, 50, 245, 240,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x121fee,
        len: 76,
        digest: [
            164, 181, 160, 201, 219, 137, 155, 133, 143, 234, 46, 254, 58, 217, 65, 206, 56, 116,
            168, 190, 41, 152, 1, 30, 19, 84, 27, 58, 2, 236, 4, 21,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 100,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x1231e0,
        len: 458,
        digest: [
            255, 163, 18, 154, 243, 9, 245, 58, 52, 82, 97, 34, 195, 142, 228, 96, 167, 199, 206,
            84, 134, 84, 27, 117, 105, 112, 218, 229, 243, 200, 52, 23,
        ],
        relocations: &[Relocation {
            at: 251,
            width: 3,
            role: 101,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x124d12,
        len: 10,
        digest: [
            77, 53, 202, 96, 1, 176, 195, 58, 29, 211, 12, 127, 181, 65, 32, 51, 226, 10, 42, 246,
            182, 178, 231, 83, 225, 26, 225, 81, 90, 146, 143, 56,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x127ace,
        len: 10,
        digest: [
            94, 123, 201, 76, 38, 230, 9, 126, 229, 164, 225, 29, 212, 166, 219, 71, 54, 44, 215,
            73, 119, 75, 209, 56, 245, 172, 95, 241, 44, 235, 154, 61,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13084a,
        len: 10,
        digest: [
            133, 67, 36, 243, 62, 153, 18, 42, 166, 85, 171, 10, 44, 201, 87, 64, 115, 119, 189,
            234, 31, 154, 13, 51, 167, 142, 166, 195, 179, 144, 32, 69,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x130854,
        len: 58,
        digest: [
            169, 130, 107, 227, 185, 81, 12, 136, 233, 246, 113, 110, 202, 228, 9, 19, 173, 43,
            237, 140, 25, 71, 167, 210, 117, 133, 245, 77, 67, 147, 75, 93,
        ],
        relocations: &[Relocation {
            at: 27,
            width: 3,
            role: 112,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13336a,
        len: 30,
        digest: [
            203, 58, 127, 105, 101, 247, 141, 109, 28, 23, 252, 98, 174, 44, 218, 184, 161, 96,
            183, 76, 123, 74, 169, 12, 138, 47, 52, 168, 183, 181, 165, 72,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x133732,
        len: 266,
        digest: [
            46, 205, 152, 33, 91, 0, 167, 5, 122, 53, 228, 232, 50, 48, 124, 23, 28, 127, 6, 1, 86,
            231, 238, 172, 85, 196, 8, 83, 159, 44, 241, 147,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 107,
                offset: 0,
            },
            Relocation {
                at: 31,
                width: 3,
                role: 107,
                offset: 0,
            },
            Relocation {
                at: 55,
                width: 3,
                role: 107,
                offset: 0,
            },
            Relocation {
                at: 79,
                width: 3,
                role: 107,
                offset: 0,
            },
            Relocation {
                at: 103,
                width: 3,
                role: 107,
                offset: 0,
            },
            Relocation {
                at: 127,
                width: 3,
                role: 107,
                offset: 0,
            },
            Relocation {
                at: 151,
                width: 3,
                role: 107,
                offset: 0,
            },
            Relocation {
                at: 175,
                width: 3,
                role: 107,
                offset: 0,
            },
            Relocation {
                at: 199,
                width: 3,
                role: 107,
                offset: 0,
            },
            Relocation {
                at: 223,
                width: 3,
                role: 107,
                offset: 0,
            },
            Relocation {
                at: 247,
                width: 3,
                role: 107,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13bc60,
        len: 10,
        digest: [
            106, 99, 145, 208, 106, 144, 207, 123, 150, 140, 156, 125, 188, 88, 203, 188, 123, 25,
            19, 116, 88, 207, 2, 57, 76, 118, 112, 204, 130, 10, 119, 16,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13d3f0,
        len: 12,
        digest: [
            214, 153, 195, 134, 42, 123, 59, 165, 220, 88, 246, 153, 53, 101, 179, 53, 112, 16,
            238, 241, 121, 135, 51, 162, 59, 74, 126, 9, 47, 229, 205, 131,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 112,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13de10,
        len: 10,
        digest: [
            184, 76, 157, 67, 75, 65, 9, 141, 120, 93, 153, 249, 47, 9, 164, 248, 255, 79, 170,
            197, 203, 230, 133, 54, 7, 124, 110, 36, 162, 73, 18, 245,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13de1a,
        len: 32,
        digest: [
            117, 114, 105, 64, 165, 119, 63, 127, 19, 224, 194, 165, 243, 155, 2, 146, 88, 178, 59,
            156, 55, 185, 61, 70, 114, 95, 73, 245, 217, 65, 229, 86,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13e2e0,
        len: 10,
        digest: [
            116, 138, 46, 202, 0, 208, 170, 1, 189, 158, 180, 166, 244, 163, 18, 139, 187, 170,
            188, 225, 140, 216, 17, 140, 95, 226, 14, 55, 55, 49, 36, 230,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13f04c,
        len: 32,
        digest: [
            185, 212, 71, 40, 157, 75, 93, 206, 74, 108, 63, 9, 250, 156, 125, 214, 69, 172, 178,
            198, 125, 51, 218, 215, 227, 228, 152, 243, 48, 200, 158, 144,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x14215c,
        len: 10,
        digest: [
            166, 66, 205, 248, 219, 167, 108, 239, 234, 201, 77, 133, 216, 139, 189, 249, 18, 77,
            216, 89, 145, 109, 56, 88, 118, 137, 32, 71, 9, 158, 7, 220,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x142e22,
        len: 4958,
        digest: [
            191, 115, 45, 188, 102, 79, 7, 131, 50, 126, 164, 13, 48, 113, 255, 57, 21, 54, 150,
            28, 224, 29, 33, 105, 169, 255, 147, 238, 61, 7, 217, 62,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x1584c8,
        len: 12,
        digest: [
            151, 52, 27, 57, 67, 215, 157, 134, 58, 218, 242, 65, 99, 182, 118, 125, 56, 215, 21,
            18, 158, 34, 229, 69, 19, 107, 184, 106, 102, 100, 174, 27,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 112,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x15c19c,
        len: 44,
        digest: [
            196, 240, 90, 90, 140, 5, 244, 44, 223, 205, 179, 254, 129, 2, 8, 8, 218, 227, 5, 200,
            236, 231, 228, 166, 242, 171, 107, 158, 242, 160, 184, 204,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x168894,
        len: 28,
        digest: [
            115, 128, 10, 112, 32, 6, 133, 206, 224, 71, 100, 157, 91, 152, 64, 158, 127, 233, 179,
            45, 162, 144, 52, 19, 172, 228, 191, 167, 185, 105, 27, 94,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x16bdda,
        len: 46,
        digest: [
            186, 205, 117, 177, 129, 255, 219, 143, 224, 108, 91, 109, 145, 122, 177, 196, 9, 252,
            112, 220, 109, 150, 221, 92, 38, 44, 22, 154, 23, 191, 197, 9,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x16be08,
        len: 10,
        digest: [
            74, 233, 209, 57, 132, 77, 120, 52, 61, 144, 59, 173, 123, 190, 144, 131, 148, 199,
            114, 210, 24, 191, 20, 6, 8, 204, 183, 141, 134, 169, 0, 146,
        ],
        relocations: &[Relocation {
            at: 5,
            width: 3,
            role: 8,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x16be58,
        len: 286,
        digest: [
            162, 12, 71, 39, 136, 104, 27, 31, 14, 211, 248, 122, 154, 67, 207, 248, 153, 43, 54,
            84, 243, 213, 213, 87, 162, 253, 194, 76, 157, 196, 215, 32,
        ],
        relocations: &[Relocation {
            at: 77,
            width: 3,
            role: 8,
            offset: 50,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x16bf76,
        len: 70,
        digest: [
            208, 84, 112, 139, 115, 124, 197, 77, 144, 106, 122, 127, 56, 66, 255, 161, 73, 98,
            199, 100, 71, 6, 222, 113, 33, 146, 73, 244, 76, 132, 109, 147,
        ],
        relocations: &[Relocation {
            at: 57,
            width: 3,
            role: 122,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x16c02c,
        len: 30,
        digest: [
            13, 47, 29, 81, 236, 247, 220, 65, 151, 235, 28, 205, 180, 85, 52, 88, 125, 246, 29,
            100, 137, 51, 97, 248, 98, 155, 36, 240, 94, 75, 191, 213,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x16c04a,
        len: 50,
        digest: [
            102, 201, 134, 246, 216, 61, 57, 227, 82, 118, 113, 54, 142, 160, 0, 19, 196, 150, 1,
            109, 50, 173, 81, 11, 181, 240, 103, 188, 30, 255, 195, 161,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x4585a4/part0
    Span {
        component: Component::Normal,
        start: 0x485a4,
        len: 1882,
        digest: [
            36, 134, 228, 67, 203, 223, 107, 36, 97, 62, 168, 136, 51, 38, 229, 92, 13, 215, 105,
            137, 15, 34, 191, 240, 70, 164, 207, 154, 1, 80, 93, 214,
        ],
        relocations: &[
            Relocation {
                at: 421,
                width: 3,
                role: 126,
                offset: 856,
            },
            Relocation {
                at: 605,
                width: 3,
                role: 126,
                offset: 856,
            },
            Relocation {
                at: 1305,
                width: 3,
                role: 126,
                offset: 1864,
            },
            Relocation {
                at: 1503,
                width: 3,
                role: 126,
                offset: 1864,
            },
        ],
    },
    // ordinary-prefix/0x458d16/part0
    Span {
        component: Component::Normal,
        start: 0x48d16,
        len: 64,
        digest: [
            54, 73, 98, 131, 108, 181, 60, 60, 131, 207, 216, 141, 158, 167, 249, 54, 85, 150, 234,
            186, 170, 181, 229, 164, 136, 64, 28, 38, 251, 60, 32, 41,
        ],
        relocations: &[
            Relocation {
                at: 23,
                width: 3,
                role: 119,
                offset: 0,
            },
            Relocation {
                at: 33,
                width: 3,
                role: 139,
                offset: 0,
            },
        ],
    },
    // ordinary-prefix/0x458e92/part0
    Span {
        component: Component::Normal,
        start: 0x48e92,
        len: 52,
        digest: [
            237, 79, 162, 22, 117, 97, 193, 47, 153, 192, 197, 0, 102, 87, 161, 207, 15, 222, 228,
            198, 200, 231, 15, 226, 131, 9, 108, 124, 52, 113, 184, 43,
        ],
        relocations: &[
            Relocation {
                at: 23,
                width: 3,
                role: 119,
                offset: 0,
            },
            Relocation {
                at: 33,
                width: 3,
                role: 139,
                offset: 0,
            },
            Relocation {
                at: 41,
                width: 3,
                role: 131,
                offset: 0,
            },
            Relocation {
                at: 45,
                width: 3,
                role: 130,
                offset: 0,
            },
        ],
    },
    // ordinary-prefix/0x458ec6/part0
    Span {
        component: Component::Normal,
        start: 0x48ec6,
        len: 128,
        digest: [
            127, 207, 153, 227, 99, 53, 70, 234, 20, 179, 124, 161, 214, 216, 94, 21, 116, 254,
            137, 118, 134, 63, 72, 133, 94, 111, 17, 89, 117, 124, 69, 118,
        ],
        relocations: &[
            Relocation {
                at: 27,
                width: 3,
                role: 127,
                offset: 0,
            },
            Relocation {
                at: 93,
                width: 3,
                role: 137,
                offset: 0,
            },
            Relocation {
                at: 99,
                width: 3,
                role: 133,
                offset: 0,
            },
            Relocation {
                at: 107,
                width: 3,
                role: 134,
                offset: 0,
            },
        ],
    },
    // ordinary-prefix/0x458f46/part0
    Span {
        component: Component::Normal,
        start: 0x48f46,
        len: 172,
        digest: [
            241, 166, 146, 125, 163, 104, 114, 179, 158, 184, 110, 20, 161, 93, 41, 207, 188, 250,
            174, 248, 59, 109, 105, 54, 164, 234, 6, 250, 193, 119, 232, 133,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x458ff2/part0
    Span {
        component: Component::Normal,
        start: 0x48ff2,
        len: 288,
        digest: [
            150, 202, 228, 49, 13, 217, 225, 229, 72, 138, 120, 115, 194, 178, 250, 170, 158, 85,
            98, 22, 254, 76, 242, 110, 104, 191, 160, 226, 144, 66, 163, 162,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x459112/part0
    Span {
        component: Component::Normal,
        start: 0x49112,
        len: 270,
        digest: [
            20, 79, 85, 211, 78, 65, 44, 70, 235, 130, 94, 16, 182, 41, 26, 91, 110, 188, 116, 183,
            129, 177, 28, 59, 242, 206, 10, 0, 78, 202, 241, 48,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x45aef4/part0
    Span {
        component: Component::Normal,
        start: 0x4aef4,
        len: 132,
        digest: [
            119, 30, 128, 146, 60, 216, 173, 243, 128, 84, 159, 76, 148, 226, 89, 40, 152, 29, 101,
            91, 246, 89, 209, 113, 55, 35, 44, 119, 55, 85, 255, 6,
        ],
        relocations: &[
            Relocation {
                at: 53,
                width: 3,
                role: 135,
                offset: 0,
            },
            Relocation {
                at: 123,
                width: 3,
                role: 136,
                offset: 0,
            },
        ],
    },
    // ordinary-prefix/0x45af78/part0
    Span {
        component: Component::Normal,
        start: 0x4af78,
        len: 190,
        digest: [
            157, 179, 225, 96, 77, 249, 177, 202, 145, 184, 198, 17, 0, 255, 125, 134, 168, 1, 232,
            39, 179, 57, 89, 37, 113, 182, 138, 85, 73, 101, 116, 22,
        ],
        relocations: &[Relocation {
            at: 93,
            width: 3,
            role: 127,
            offset: 0,
        }],
    },
    // ordinary-prefix/0x45b514/part0
    Span {
        component: Component::Normal,
        start: 0x4b514,
        len: 8,
        digest: [
            226, 170, 78, 229, 31, 183, 159, 234, 165, 15, 201, 176, 166, 240, 37, 85, 195, 117,
            167, 189, 147, 183, 204, 60, 196, 207, 247, 227, 29, 95, 30, 47,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x45b51c/part0
    Span {
        component: Component::Normal,
        start: 0x4b51c,
        len: 16,
        digest: [
            164, 121, 73, 90, 127, 244, 0, 164, 211, 232, 7, 124, 64, 154, 247, 171, 246, 118, 192,
            166, 253, 89, 9, 78, 243, 94, 180, 100, 186, 77, 77, 69,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x45b52c/part0
    Span {
        component: Component::Normal,
        start: 0x4b52c,
        len: 84,
        digest: [
            240, 137, 235, 212, 120, 141, 122, 19, 163, 120, 121, 169, 239, 212, 153, 114, 108,
            191, 143, 129, 188, 9, 220, 29, 176, 188, 139, 225, 10, 71, 158, 114,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x578894/part0
    Span {
        component: Component::Normal,
        start: 0x168894,
        len: 28,
        digest: [
            115, 128, 10, 112, 32, 6, 133, 206, 224, 71, 100, 157, 91, 152, 64, 158, 127, 233, 179,
            45, 162, 144, 52, 19, 172, 228, 191, 167, 185, 105, 27, 94,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x5788de/part0
    Span {
        component: Component::Normal,
        start: 0x1688de,
        len: 20,
        digest: [
            129, 49, 240, 60, 184, 221, 89, 197, 173, 216, 230, 54, 111, 222, 131, 141, 101, 159,
            125, 11, 58, 172, 58, 63, 93, 251, 15, 103, 18, 162, 31, 13,
        ],
        relocations: &[],
    },
    // kernel-entry/0x400276/part0
    Span {
        component: Component::Kernel,
        start: 0x276,
        len: 416,
        digest: [
            205, 27, 140, 159, 23, 188, 213, 121, 93, 139, 114, 199, 239, 51, 168, 109, 126, 227,
            205, 63, 25, 215, 98, 175, 137, 37, 21, 73, 25, 119, 46, 173,
        ],
        relocations: &[Relocation {
            at: 5,
            width: 3,
            role: 143,
            offset: 0,
        }],
    },
    // kernel-entry/0x40554e/part0
    Span {
        component: Component::Kernel,
        start: 0x554e,
        len: 188,
        digest: [
            85, 249, 64, 80, 240, 164, 119, 183, 43, 191, 106, 108, 109, 238, 42, 220, 129, 97,
            212, 76, 119, 168, 189, 110, 123, 137, 95, 90, 32, 119, 177, 10,
        ],
        relocations: &[],
    },
    // kernel-entry/0x40490c/part0
    Span {
        component: Component::Kernel,
        start: 0x490c,
        len: 6,
        digest: [
            94, 187, 145, 244, 80, 44, 237, 146, 165, 8, 98, 84, 219, 129, 8, 133, 113, 7, 42, 216,
            48, 148, 179, 134, 143, 107, 245, 36, 210, 152, 104, 58,
        ],
        relocations: &[Relocation {
            at: 1,
            width: 3,
            role: 0,
            offset: 0,
        }],
    },
    // kernel-entry/0x4060f6/part0
    Span {
        component: Component::Kernel,
        start: 0x60f6,
        len: 46,
        digest: [
            238, 133, 123, 174, 199, 166, 59, 225, 70, 244, 142, 15, 182, 169, 1, 56, 149, 198,
            171, 99, 97, 239, 165, 223, 107, 53, 163, 199, 123, 136, 115, 203,
        ],
        relocations: &[],
    },
    // query-diagnostic/548abe/part0
    Span {
        component: Component::Normal,
        start: 0x138abe,
        len: 8,
        digest: [
            152, 69, 193, 233, 183, 175, 174, 88, 106, 255, 242, 222, 120, 97, 98, 228, 227, 68,
            255, 68, 78, 225, 196, 74, 25, 109, 111, 24, 208, 239, 199, 8,
        ],
        relocations: &[],
    },
    // query-diagnostic/548bae/part0
    Span {
        component: Component::Normal,
        start: 0x138bae,
        len: 78,
        digest: [
            120, 68, 66, 228, 159, 140, 254, 194, 195, 29, 190, 58, 227, 153, 78, 91, 23, 45, 254,
            127, 38, 112, 205, 202, 72, 153, 192, 39, 130, 154, 85, 14,
        ],
        relocations: &[
            Relocation {
                at: 31,
                width: 3,
                role: 144,
                offset: 0,
            },
            Relocation {
                at: 69,
                width: 3,
                role: 146,
                offset: 0,
            },
        ],
    },
    // query-diagnostic/549596/part0
    Span {
        component: Component::Normal,
        start: 0x139596,
        len: 574,
        digest: [
            139, 222, 12, 205, 70, 183, 157, 57, 104, 15, 211, 78, 54, 230, 226, 244, 84, 122, 72,
            157, 57, 63, 30, 245, 91, 255, 68, 175, 252, 39, 229, 108,
        ],
        relocations: &[
            Relocation {
                at: 179,
                width: 3,
                role: 148,
                offset: 0,
            },
            Relocation {
                at: 255,
                width: 3,
                role: 147,
                offset: 0,
            },
            Relocation {
                at: 269,
                width: 3,
                role: 149,
                offset: 0,
            },
            Relocation {
                at: 467,
                width: 3,
                role: 148,
                offset: 0,
            },
        ],
    },
    // query-diagnostic/5497d4/part0
    Span {
        component: Component::Normal,
        start: 0x1397d4,
        len: 158,
        digest: [
            64, 13, 47, 100, 133, 135, 1, 47, 230, 58, 207, 165, 170, 174, 116, 146, 220, 147, 158,
            241, 8, 170, 60, 225, 235, 52, 222, 187, 144, 88, 128, 60,
        ],
        relocations: &[
            Relocation {
                at: 9,
                width: 3,
                role: 148,
                offset: 0,
            },
            Relocation {
                at: 57,
                width: 3,
                role: 149,
                offset: 0,
            },
        ],
    },
    // query-diagnostic/549872/part0
    Span {
        component: Component::Normal,
        start: 0x139872,
        len: 26,
        digest: [
            166, 180, 5, 198, 178, 96, 218, 164, 31, 206, 112, 183, 93, 243, 187, 196, 152, 48, 34,
            226, 225, 108, 18, 248, 197, 8, 226, 57, 147, 188, 50, 189,
        ],
        relocations: &[],
    },
    // query-diagnostic/54de7e/part0
    Span {
        component: Component::Normal,
        start: 0x13de7e,
        len: 10,
        digest: [
            252, 203, 122, 95, 185, 26, 194, 78, 68, 121, 111, 255, 244, 35, 91, 128, 145, 242,
            142, 93, 196, 226, 63, 161, 3, 151, 79, 146, 59, 59, 176, 123,
        ],
        relocations: &[],
    },
    // normal-query
    Span {
        component: Component::Normal,
        start: 0x16ba40,
        len: 118,
        digest: [
            77, 142, 241, 118, 0, 233, 18, 166, 134, 149, 2, 138, 235, 249, 195, 232, 179, 59, 226,
            24, 120, 109, 207, 121, 52, 109, 189, 80, 3, 73, 178, 83,
        ],
        relocations: &[Relocation {
            at: 61,
            width: 3,
            role: 145,
            offset: 0,
        }],
    },
    // normal-builder
    Span {
        component: Component::Normal,
        start: 0x16bae4,
        len: 120,
        digest: [
            46, 53, 32, 112, 90, 141, 81, 205, 161, 120, 91, 14, 4, 223, 163, 224, 71, 200, 205,
            163, 219, 18, 204, 38, 239, 212, 189, 47, 59, 218, 75, 158,
        ],
        relocations: &[],
    },
    // diagnostic-fixed-copy-source
    Span {
        component: Component::Normal,
        start: 0x190aa2,
        len: 8,
        digest: [
            124, 127, 215, 239, 0, 243, 83, 224, 121, 116, 107, 175, 219, 248, 228, 161, 16, 36,
            23, 94, 194, 77, 30, 175, 236, 194, 63, 164, 246, 38, 97, 36,
        ],
        relocations: &[],
    },
    // kernel-clear-wrapper
    Span {
        component: Component::Normal,
        start: 0x47700,
        len: 6,
        digest: [
            94, 187, 145, 244, 80, 44, 237, 146, 165, 8, 98, 84, 219, 129, 8, 133, 113, 7, 42, 216,
            48, 148, 179, 134, 143, 107, 245, 36, 210, 152, 104, 58,
        ],
        relocations: &[Relocation {
            at: 1,
            width: 3,
            role: 164,
            offset: 0,
        }],
    },
    // predispatch-port-leaf
    Span {
        component: Component::Normal,
        start: 0xdd09c,
        len: 12,
        digest: [
            223, 3, 16, 153, 42, 201, 73, 208, 61, 190, 169, 44, 232, 138, 5, 58, 233, 67, 13, 160,
            180, 58, 177, 104, 175, 36, 192, 147, 245, 167, 8, 221,
        ],
        relocations: &[],
    },
    // bank-adjacent-call-prefix
    Span {
        component: Component::Normal,
        start: 0x4edd6,
        len: 12,
        digest: [
            34, 220, 68, 55, 188, 193, 191, 134, 106, 171, 240, 44, 95, 15, 147, 31, 6, 211, 124,
            132, 156, 225, 40, 186, 92, 114, 115, 216, 79, 82, 59, 224,
        ],
        relocations: &[
            Relocation {
                at: 5,
                width: 3,
                role: 156,
                offset: 0,
            },
            Relocation {
                at: 9,
                width: 3,
                role: 157,
                offset: 0,
            },
        ],
    },
    // bank-capacity-producer
    Span {
        component: Component::Normal,
        start: 0x13c37e,
        len: 50,
        digest: [
            63, 176, 78, 29, 89, 224, 94, 103, 136, 154, 161, 25, 27, 9, 56, 126, 8, 184, 109, 149,
            129, 147, 166, 199, 70, 0, 5, 248, 237, 31, 8, 16,
        ],
        relocations: &[],
    },
    // bank-validator
    Span {
        component: Component::Normal,
        start: 0x13c3b0,
        len: 156,
        digest: [
            241, 5, 226, 228, 51, 103, 212, 219, 118, 24, 73, 191, 55, 235, 206, 72, 215, 198, 78,
            60, 198, 167, 111, 251, 4, 68, 111, 109, 193, 63, 65, 74,
        ],
        relocations: &[Relocation {
            at: 139,
            width: 3,
            role: 158,
            offset: 0,
        }],
    },
    // bank-loader-helper
    Span {
        component: Component::Normal,
        start: 0x9ec3a,
        len: 18,
        digest: [
            163, 36, 161, 252, 238, 20, 239, 156, 231, 55, 55, 16, 89, 192, 198, 114, 180, 246, 12,
            24, 182, 83, 26, 180, 20, 103, 66, 237, 127, 133, 164, 177,
        ],
        relocations: &[
            Relocation {
                at: 3,
                width: 3,
                role: 159,
                offset: 0,
            },
            Relocation {
                at: 9,
                width: 3,
                role: 160,
                offset: 0,
            },
        ],
    },
    // bank-loader-wrapper/2
    Span {
        component: Component::Normal,
        start: 0x476be,
        len: 6,
        digest: [
            209, 190, 47, 118, 27, 60, 193, 182, 112, 115, 147, 217, 98, 56, 33, 197, 188, 171, 18,
            74, 120, 195, 224, 237, 2, 14, 235, 60, 242, 239, 224, 52,
        ],
        relocations: &[],
    },
    // bank-loader-wrapper/8
    Span {
        component: Component::Normal,
        start: 0x476c4,
        len: 6,
        digest: [
            229, 212, 181, 246, 50, 90, 77, 39, 70, 223, 163, 183, 155, 78, 120, 173, 139, 253, 14,
            49, 25, 166, 157, 38, 35, 54, 119, 72, 170, 188, 165, 8,
        ],
        relocations: &[],
    },
    // warm-entry-flag
    Span {
        component: Component::Kernel,
        start: 0x100,
        len: 8,
        digest: [
            224, 122, 191, 21, 1, 251, 255, 9, 87, 97, 69, 17, 238, 181, 100, 196, 163, 43, 108,
            115, 92, 14, 56, 244, 246, 209, 188, 13, 28, 40, 217, 121,
        ],
        relocations: &[],
    },
    // kernel-successful-root
    Span {
        component: Component::Kernel,
        start: 0x108,
        len: 336,
        digest: [
            8, 3, 190, 97, 188, 46, 205, 4, 31, 131, 183, 66, 122, 98, 175, 25, 52, 171, 78, 128,
            54, 236, 153, 78, 214, 71, 135, 120, 250, 75, 135, 14,
        ],
        relocations: &[
            Relocation {
                at: 73,
                width: 3,
                role: 173,
                offset: 0,
            },
            Relocation {
                at: 111,
                width: 3,
                role: 173,
                offset: 0,
            },
            Relocation {
                at: 135,
                width: 3,
                role: 140,
                offset: 0,
            },
            Relocation {
                at: 159,
                width: 3,
                role: 141,
                offset: 0,
            },
            Relocation {
                at: 179,
                width: 3,
                role: 162,
                offset: 336,
            },
            Relocation {
                at: 209,
                width: 3,
                role: 162,
                offset: 336,
            },
            Relocation {
                at: 327,
                width: 3,
                role: 142,
                offset: 0,
            },
        ],
    },
    // kernel-early-copied-block
    Span {
        component: Component::Kernel,
        start: 0x4c6,
        len: 786,
        digest: [
            51, 228, 196, 176, 204, 200, 159, 194, 254, 39, 176, 15, 202, 179, 2, 248, 163, 169,
            181, 182, 34, 139, 131, 233, 237, 237, 246, 193, 200, 187, 8, 37,
        ],
        relocations: &[],
    },
    // kernel-clear-trampoline
    Span {
        component: Component::Kernel,
        start: 0xa5c,
        len: 4,
        digest: [
            169, 98, 201, 154, 224, 102, 100, 21, 231, 142, 251, 150, 186, 177, 3, 159, 64, 74,
            190, 159, 155, 232, 142, 49, 126, 231, 228, 196, 115, 223, 170, 50,
        ],
        relocations: &[Relocation {
            at: 1,
            width: 3,
            role: 165,
            offset: 0,
        }],
    },
    // kernel-clear-body
    Span {
        component: Component::Kernel,
        start: 0x4b2,
        len: 20,
        digest: [
            201, 206, 50, 4, 196, 217, 28, 182, 232, 165, 143, 5, 111, 252, 15, 65, 15, 94, 255,
            23, 13, 247, 132, 177, 219, 90, 168, 207, 243, 86, 146, 165,
        ],
        relocations: &[Relocation {
            at: 15,
            width: 3,
            role: 173,
            offset: 0,
        }],
    },
    // kernel-startup-runtime-entry
    Span {
        component: Component::Kernel,
        start: 0xb6f4,
        len: 26,
        digest: [
            233, 55, 81, 200, 123, 206, 10, 193, 244, 29, 132, 151, 32, 223, 190, 131, 121, 226,
            254, 194, 217, 153, 61, 141, 77, 136, 202, 141, 137, 147, 40, 166,
        ],
        relocations: &[
            Relocation {
                at: 17,
                width: 3,
                role: 170,
                offset: 0,
            },
            Relocation {
                at: 21,
                width: 3,
                role: 167,
                offset: 0,
            },
        ],
    },
    // kernel-zero-return
    Span {
        component: Component::Kernel,
        start: 0xb600,
        len: 4,
        digest: [
            38, 69, 1, 199, 28, 47, 210, 193, 124, 121, 195, 7, 83, 131, 13, 237, 155, 168, 179,
            172, 225, 68, 249, 60, 44, 57, 152, 165, 27, 82, 9, 166,
        ],
        relocations: &[],
    },
    // kernel-ccr-helper
    Span {
        component: Component::Kernel,
        start: 0xb9c2,
        len: 20,
        digest: [
            16, 24, 71, 232, 105, 23, 248, 115, 91, 103, 88, 49, 41, 239, 163, 238, 194, 12, 177,
            230, 19, 20, 80, 98, 143, 111, 151, 31, 50, 134, 67, 30,
        ],
        relocations: &[],
    },
    // kernel-pool-init
    Span {
        component: Component::Kernel,
        start: 0xccdc,
        len: 18,
        digest: [
            11, 116, 53, 119, 174, 189, 109, 158, 132, 255, 114, 142, 120, 255, 247, 128, 67, 197,
            176, 17, 172, 164, 11, 238, 49, 143, 26, 135, 134, 95, 243, 231,
        ],
        relocations: &[],
    },
    // kernel-runtime-init
    Span {
        component: Component::Kernel,
        start: 0xba56,
        len: 1370,
        digest: [
            251, 171, 119, 214, 92, 82, 241, 232, 134, 153, 88, 89, 209, 151, 5, 169, 198, 13, 27,
            103, 64, 191, 158, 165, 160, 0, 84, 168, 50, 31, 227, 132,
        ],
        relocations: &[
            Relocation {
                at: 13,
                width: 3,
                role: 168,
                offset: 0,
            },
            Relocation {
                at: 149,
                width: 3,
                role: 169,
                offset: 0,
            },
            Relocation {
                at: 183,
                width: 3,
                role: 169,
                offset: 0,
            },
            Relocation {
                at: 219,
                width: 3,
                role: 169,
                offset: 0,
            },
        ],
    },
    // kernel-runtime-descriptor
    Span {
        component: Component::Kernel,
        start: 0xff2a,
        len: 124,
        digest: [
            15, 155, 34, 131, 206, 167, 187, 113, 62, 161, 127, 31, 99, 19, 79, 123, 176, 90, 132,
            126, 86, 188, 149, 109, 104, 165, 75, 57, 90, 101, 14, 234,
        ],
        relocations: &[],
    },
    // kernel-copy-wrapper
    Span {
        component: Component::Kernel,
        start: 0x5d20,
        len: 24,
        digest: [
            22, 51, 165, 244, 48, 233, 184, 219, 9, 215, 36, 105, 153, 187, 19, 151, 148, 188, 44,
            7, 112, 154, 202, 220, 162, 51, 202, 186, 65, 2, 192, 168,
        ],
        relocations: &[Relocation {
            at: 15,
            width: 3,
            role: 174,
            offset: 0,
        }],
    },
    // kernel-clear-wrapper
    Span {
        component: Component::Kernel,
        start: 0x5d38,
        len: 18,
        digest: [
            47, 189, 110, 221, 49, 130, 252, 242, 163, 69, 58, 22, 192, 109, 126, 213, 218, 129,
            53, 85, 172, 28, 114, 122, 28, 191, 186, 210, 17, 111, 33, 224,
        ],
        relocations: &[Relocation {
            at: 11,
            width: 3,
            role: 175,
            offset: 0,
        }],
    },
    // kernel-copy-adapter
    Span {
        component: Component::Kernel,
        start: 0x68be,
        len: 30,
        digest: [
            13, 47, 29, 81, 236, 247, 220, 65, 151, 235, 28, 205, 180, 85, 52, 88, 125, 246, 29,
            100, 137, 51, 97, 248, 98, 155, 36, 240, 94, 75, 191, 213,
        ],
        relocations: &[],
    },
    // kernel-fill-body
    Span {
        component: Component::Kernel,
        start: 0x68dc,
        len: 50,
        digest: [
            102, 201, 134, 246, 216, 61, 57, 227, 82, 118, 113, 54, 142, 160, 0, 19, 196, 150, 1,
            109, 50, 173, 81, 11, 181, 240, 103, 188, 30, 255, 195, 161,
        ],
        relocations: &[],
    },
    // kernel-initial-data0
    Span {
        component: Component::Kernel,
        start: 0xc54,
        len: 168,
        digest: [
            204, 113, 108, 210, 224, 47, 64, 209, 242, 77, 250, 242, 243, 118, 109, 98, 95, 119,
            86, 214, 64, 254, 71, 60, 69, 237, 112, 73, 37, 16, 89, 199,
        ],
        relocations: &[],
    },
    // kernel-initial-data1
    Span {
        component: Component::Kernel,
        start: 0x673a,
        len: 24,
        digest: [
            254, 232, 27, 58, 172, 130, 24, 123, 99, 239, 36, 213, 242, 155, 10, 132, 182, 152,
            115, 231, 80, 137, 223, 180, 211, 12, 127, 239, 217, 114, 169, 110,
        ],
        relocations: &[],
    },
    // kernel-initial-data2
    Span {
        component: Component::Kernel,
        start: 0x6124,
        len: 16,
        digest: [
            64, 94, 43, 63, 115, 40, 178, 23, 34, 151, 11, 201, 29, 138, 164, 208, 166, 175, 197,
            149, 83, 113, 5, 226, 66, 36, 64, 54, 118, 156, 104, 16,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_query
    Span {
        component: Component::Kernel,
        start: 0x65c,
        len: 64,
        digest: [
            0, 132, 22, 205, 205, 5, 22, 64, 216, 170, 146, 220, 168, 63, 115, 89, 166, 9, 118,
            233, 2, 192, 31, 127, 109, 16, 165, 98, 46, 59, 148, 191,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_builder
    Span {
        component: Component::Kernel,
        start: 0x6ca,
        len: 120,
        digest: [
            46, 53, 32, 112, 90, 141, 81, 205, 161, 120, 91, 14, 4, 223, 163, 224, 71, 200, 205,
            163, 219, 18, 204, 38, 239, 212, 189, 47, 59, 218, 75, 158,
        ],
        relocations: &[],
    },
    // exact-comparison/normal_builder
    Span {
        component: Component::Normal,
        start: 0x16bae4,
        len: 120,
        digest: [
            46, 53, 32, 112, 90, 141, 81, 205, 161, 120, 91, 14, 4, 223, 163, 224, 71, 200, 205,
            163, 219, 18, 204, 38, 239, 212, 189, 47, 59, 218, 75, 158,
        ],
        relocations: &[],
    },
    // exact-comparison/normal_query_prefix
    Span {
        component: Component::Normal,
        start: 0x16ba40,
        len: 20,
        digest: [
            37, 38, 219, 31, 18, 81, 57, 240, 16, 213, 190, 129, 156, 159, 46, 113, 124, 51, 244,
            187, 115, 212, 195, 8, 185, 152, 139, 70, 143, 17, 131, 83,
        ],
        relocations: &[],
    },
    // exact-comparison/normal_query_tail
    Span {
        component: Component::Normal,
        start: 0x16ba80,
        len: 54,
        digest: [
            38, 19, 168, 241, 100, 117, 47, 39, 204, 144, 121, 117, 67, 9, 38, 135, 85, 84, 64,
            129, 186, 139, 179, 211, 243, 116, 32, 109, 136, 24, 44, 0,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_zero_return
    Span {
        component: Component::Kernel,
        start: 0xb600,
        len: 4,
        digest: [
            38, 69, 1, 199, 28, 47, 210, 193, 124, 121, 195, 7, 83, 131, 13, 237, 155, 168, 179,
            172, 225, 68, 249, 60, 44, 57, 152, 165, 27, 82, 9, 166,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_runtime_init
    Span {
        component: Component::Kernel,
        start: 0xba56,
        len: 1370,
        digest: [
            144, 131, 168, 56, 27, 239, 155, 179, 234, 217, 206, 55, 228, 185, 17, 110, 82, 129,
            12, 37, 239, 44, 214, 98, 153, 59, 245, 0, 184, 35, 55, 10,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_pool_init
    Span {
        component: Component::Kernel,
        start: 0xccdc,
        len: 18,
        digest: [
            11, 116, 53, 119, 174, 189, 109, 158, 132, 255, 114, 142, 120, 255, 247, 128, 67, 197,
            176, 17, 172, 164, 11, 238, 49, 143, 26, 135, 134, 95, 243, 231,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_runtime_parameters
    Span {
        component: Component::Kernel,
        start: 0xff2a,
        len: 124,
        digest: [
            15, 155, 34, 131, 206, 167, 187, 113, 62, 161, 127, 31, 99, 19, 79, 123, 176, 90, 132,
            126, 86, 188, 149, 109, 104, 165, 75, 57, 90, 101, 14, 234,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_native_memset
    Span {
        component: Component::Kernel,
        start: 0x68dc,
        len: 50,
        digest: [
            102, 201, 134, 246, 216, 61, 57, 227, 82, 118, 113, 54, 142, 160, 0, 19, 196, 150, 1,
            109, 50, 173, 81, 11, 181, 240, 103, 188, 30, 255, 195, 161,
        ],
        relocations: &[],
    },
];
const ROLES_1: &[Span] = &[
    // normal-entry-vector
    Span {
        component: Component::Normal,
        start: 0x2000,
        len: 4,
        digest: [
            169, 98, 201, 154, 224, 102, 100, 21, 231, 142, 251, 150, 186, 177, 3, 159, 64, 74,
            190, 159, 155, 232, 142, 49, 126, 231, 228, 196, 115, 223, 170, 50,
        ],
        relocations: &[Relocation {
            at: 1,
            width: 3,
            role: 4,
            offset: 0,
        }],
    },
    // normal-copied-source_cpu
    Span {
        component: Component::Normal,
        start: 0x16c406,
        len: 652,
        digest: [
            58, 182, 112, 103, 22, 7, 82, 205, 114, 89, 151, 187, 48, 151, 144, 56, 131, 93, 108,
            19, 52, 238, 211, 97, 233, 202, 157, 141, 97, 167, 167, 170,
        ],
        relocations: &[],
    },
    // normal-copied-body_cpu
    Span {
        component: Component::Normal,
        start: 0x16c564,
        len: 46,
        digest: [
            237, 239, 103, 242, 9, 172, 169, 191, 28, 13, 182, 171, 197, 200, 95, 63, 167, 122,
            254, 22, 133, 57, 44, 12, 48, 94, 234, 179, 179, 255, 102, 50,
        ],
        relocations: &[],
    },
    // normal-copied-copy_cpu
    Span {
        component: Component::Normal,
        start: 0x9f4ec,
        len: 20,
        digest: [
            19, 162, 232, 209, 248, 191, 100, 211, 57, 210, 141, 162, 145, 234, 190, 141, 18, 151,
            164, 94, 37, 116, 129, 75, 17, 238, 140, 12, 248, 25, 99, 77,
        ],
        relocations: &[],
    },
    // normal-copied-initializer_cpu
    Span {
        component: Component::Normal,
        start: 0x9f466,
        len: 272,
        digest: [
            106, 116, 232, 158, 161, 37, 202, 100, 204, 195, 181, 23, 150, 2, 44, 40, 4, 12, 112,
            9, 245, 235, 11, 6, 16, 151, 22, 214, 162, 80, 222, 240,
        ],
        relocations: &[
            Relocation {
                at: 155,
                width: 3,
                role: 129,
                offset: 0,
            },
            Relocation {
                at: 227,
                width: 3,
                role: 154,
                offset: 0,
            },
            Relocation {
                at: 247,
                width: 3,
                role: 15,
                offset: 0,
            },
            Relocation {
                at: 251,
                width: 3,
                role: 155,
                offset: 0,
            },
            Relocation {
                at: 255,
                width: 3,
                role: 133,
                offset: 0,
            },
            Relocation {
                at: 259,
                width: 3,
                role: 9,
                offset: 0,
            },
        ],
    },
    // normal-helpers_cpu/0
    Span {
        component: Component::Normal,
        start: 0x169418,
        len: 24,
        digest: [
            22, 51, 165, 244, 48, 233, 184, 219, 9, 215, 36, 105, 153, 187, 19, 151, 148, 188, 44,
            7, 112, 154, 202, 220, 162, 51, 202, 186, 65, 2, 192, 168,
        ],
        relocations: &[Relocation {
            at: 15,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // normal-helpers_cpu/1
    Span {
        component: Component::Normal,
        start: 0x16cada,
        len: 30,
        digest: [
            13, 47, 29, 81, 236, 247, 220, 65, 151, 235, 28, 205, 180, 85, 52, 88, 125, 246, 29,
            100, 137, 51, 97, 248, 98, 155, 36, 240, 94, 75, 191, 213,
        ],
        relocations: &[],
    },
    // normal-clear_helpers_cpu/0
    Span {
        component: Component::Normal,
        start: 0x169430,
        len: 18,
        digest: [
            47, 189, 110, 221, 49, 130, 252, 242, 163, 69, 58, 22, 192, 109, 126, 213, 218, 129,
            53, 85, 172, 28, 114, 122, 28, 191, 186, 210, 17, 111, 33, 224,
        ],
        relocations: &[Relocation {
            at: 11,
            width: 3,
            role: 8,
            offset: 0,
        }],
    },
    // normal-clear_helpers_cpu/1
    Span {
        component: Component::Normal,
        start: 0x16caf8,
        len: 50,
        digest: [
            102, 201, 134, 246, 216, 61, 57, 227, 82, 118, 113, 54, 142, 160, 0, 19, 196, 150, 1,
            109, 50, 173, 81, 11, 181, 240, 103, 188, 30, 255, 195, 161,
        ],
        relocations: &[],
    },
    // normal-root-dispatcher
    Span {
        component: Component::Normal,
        start: 0x13f834,
        len: 32,
        digest: [
            94, 155, 120, 155, 220, 93, 215, 65, 98, 17, 254, 194, 101, 81, 98, 253, 248, 35, 77,
            202, 152, 56, 125, 175, 208, 254, 204, 42, 81, 208, 249, 209,
        ],
        relocations: &[
            Relocation {
                at: 1,
                width: 3,
                role: 167,
                offset: 0,
            },
            Relocation {
                at: 5,
                width: 3,
                role: 156,
                offset: 0,
            },
            Relocation {
                at: 29,
                width: 3,
                role: 171,
                offset: 1370,
            },
        ],
    },
    // normal-initial-data-source/0
    Span {
        component: Component::Normal,
        start: 0x1a37e4,
        len: 168,
        digest: [
            250, 147, 32, 33, 235, 100, 177, 133, 218, 123, 23, 8, 32, 149, 217, 171, 172, 16, 12,
            14, 17, 203, 189, 145, 249, 215, 35, 122, 87, 75, 105, 62,
        ],
        relocations: &[],
    },
    // normal-initial-data-source/1
    Span {
        component: Component::Normal,
        start: 0x18589c,
        len: 1530,
        digest: [
            60, 243, 195, 174, 42, 16, 124, 201, 185, 252, 19, 168, 156, 124, 45, 157, 43, 249, 27,
            133, 135, 195, 98, 186, 163, 130, 245, 17, 172, 152, 6, 158,
        ],
        relocations: &[],
    },
    // normal-initial-data-source/2
    Span {
        component: Component::Normal,
        start: 0x185e96,
        len: 16,
        digest: [
            120, 23, 67, 216, 198, 136, 41, 87, 144, 198, 58, 206, 205, 191, 43, 169, 121, 129,
            152, 170, 208, 165, 230, 224, 188, 4, 20, 88, 15, 57, 171, 55,
        ],
        relocations: &[],
    },
    // normal-initial-data-source/3
    Span {
        component: Component::Normal,
        start: 0x1adb0a,
        len: 398,
        digest: [
            171, 127, 217, 22, 216, 210, 232, 226, 153, 43, 224, 190, 130, 204, 29, 4, 210, 243, 7,
            240, 202, 2, 231, 193, 27, 167, 33, 182, 35, 117, 182, 246,
        ],
        relocations: &[],
    },
    // constructor-table
    Span {
        component: Component::Normal,
        start: 0x1a388c,
        len: 208,
        digest: [
            70, 245, 49, 183, 234, 4, 40, 251, 242, 195, 202, 43, 96, 232, 220, 51, 214, 187, 250,
            0, 14, 15, 209, 180, 137, 197, 227, 145, 64, 164, 112, 6,
        ],
        relocations: &[
            Relocation {
                at: 0,
                width: 4,
                role: 16,
                offset: 0,
            },
            Relocation {
                at: 4,
                width: 4,
                role: 17,
                offset: 0,
            },
            Relocation {
                at: 8,
                width: 4,
                role: 18,
                offset: 0,
            },
            Relocation {
                at: 12,
                width: 4,
                role: 24,
                offset: 0,
            },
            Relocation {
                at: 16,
                width: 4,
                role: 39,
                offset: 0,
            },
            Relocation {
                at: 20,
                width: 4,
                role: 40,
                offset: 0,
            },
            Relocation {
                at: 24,
                width: 4,
                role: 41,
                offset: 0,
            },
            Relocation {
                at: 28,
                width: 4,
                role: 52,
                offset: 0,
            },
            Relocation {
                at: 32,
                width: 4,
                role: 53,
                offset: 0,
            },
            Relocation {
                at: 36,
                width: 4,
                role: 54,
                offset: 0,
            },
            Relocation {
                at: 40,
                width: 4,
                role: 55,
                offset: 0,
            },
            Relocation {
                at: 44,
                width: 4,
                role: 56,
                offset: 0,
            },
            Relocation {
                at: 48,
                width: 4,
                role: 57,
                offset: 0,
            },
            Relocation {
                at: 52,
                width: 4,
                role: 58,
                offset: 0,
            },
            Relocation {
                at: 56,
                width: 4,
                role: 59,
                offset: 0,
            },
            Relocation {
                at: 60,
                width: 4,
                role: 60,
                offset: 0,
            },
            Relocation {
                at: 64,
                width: 4,
                role: 64,
                offset: 0,
            },
            Relocation {
                at: 68,
                width: 4,
                role: 71,
                offset: 0,
            },
            Relocation {
                at: 72,
                width: 4,
                role: 72,
                offset: 0,
            },
            Relocation {
                at: 76,
                width: 4,
                role: 73,
                offset: 0,
            },
            Relocation {
                at: 80,
                width: 4,
                role: 74,
                offset: 0,
            },
            Relocation {
                at: 84,
                width: 4,
                role: 75,
                offset: 0,
            },
            Relocation {
                at: 88,
                width: 4,
                role: 76,
                offset: 0,
            },
            Relocation {
                at: 92,
                width: 4,
                role: 80,
                offset: 36,
            },
            Relocation {
                at: 96,
                width: 4,
                role: 82,
                offset: 0,
            },
            Relocation {
                at: 100,
                width: 4,
                role: 83,
                offset: 0,
            },
            Relocation {
                at: 104,
                width: 4,
                role: 85,
                offset: 0,
            },
            Relocation {
                at: 108,
                width: 4,
                role: 86,
                offset: 0,
            },
            Relocation {
                at: 112,
                width: 4,
                role: 88,
                offset: 0,
            },
            Relocation {
                at: 116,
                width: 4,
                role: 90,
                offset: 0,
            },
            Relocation {
                at: 120,
                width: 4,
                role: 92,
                offset: 0,
            },
            Relocation {
                at: 124,
                width: 4,
                role: 93,
                offset: 0,
            },
            Relocation {
                at: 128,
                width: 4,
                role: 94,
                offset: 0,
            },
            Relocation {
                at: 132,
                width: 4,
                role: 95,
                offset: 0,
            },
            Relocation {
                at: 136,
                width: 4,
                role: 96,
                offset: 0,
            },
            Relocation {
                at: 140,
                width: 4,
                role: 97,
                offset: 0,
            },
            Relocation {
                at: 144,
                width: 4,
                role: 99,
                offset: 0,
            },
            Relocation {
                at: 148,
                width: 4,
                role: 100,
                offset: 0,
            },
            Relocation {
                at: 152,
                width: 4,
                role: 103,
                offset: 0,
            },
            Relocation {
                at: 156,
                width: 4,
                role: 104,
                offset: 0,
            },
            Relocation {
                at: 160,
                width: 4,
                role: 105,
                offset: 0,
            },
            Relocation {
                at: 164,
                width: 4,
                role: 106,
                offset: 0,
            },
            Relocation {
                at: 168,
                width: 4,
                role: 109,
                offset: 0,
            },
            Relocation {
                at: 172,
                width: 4,
                role: 110,
                offset: 0,
            },
            Relocation {
                at: 176,
                width: 4,
                role: 111,
                offset: 0,
            },
            Relocation {
                at: 180,
                width: 4,
                role: 112,
                offset: 0,
            },
            Relocation {
                at: 184,
                width: 4,
                role: 114,
                offset: 0,
            },
            Relocation {
                at: 188,
                width: 4,
                role: 115,
                offset: 0,
            },
            Relocation {
                at: 192,
                width: 4,
                role: 116,
                offset: 0,
            },
            Relocation {
                at: 196,
                width: 4,
                role: 117,
                offset: 0,
            },
            Relocation {
                at: 200,
                width: 4,
                role: 118,
                offset: 0,
            },
            Relocation {
                at: 204,
                width: 4,
                role: 119,
                offset: 0,
            },
        ],
    },
    // constructor-dispatcher
    Span {
        component: Component::Normal,
        start: 0x16c854,
        len: 34,
        digest: [
            193, 78, 194, 45, 205, 64, 13, 140, 247, 195, 191, 157, 4, 113, 149, 79, 187, 22, 165,
            193, 232, 57, 35, 78, 181, 60, 239, 186, 140, 39, 35, 198,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x4648,
        len: 10,
        digest: [
            239, 3, 17, 106, 169, 150, 79, 62, 170, 86, 68, 5, 95, 172, 50, 170, 115, 189, 36, 187,
            184, 13, 160, 133, 59, 218, 24, 26, 184, 38, 62, 157,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x4b80,
        len: 22,
        digest: [
            26, 234, 184, 181, 33, 233, 15, 25, 59, 180, 39, 187, 40, 104, 64, 255, 126, 112, 135,
            214, 85, 45, 220, 129, 200, 85, 92, 229, 51, 11, 54, 140,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 120,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 120,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x4de4,
        len: 40,
        digest: [
            108, 52, 249, 81, 121, 22, 30, 197, 234, 171, 51, 162, 84, 57, 136, 159, 187, 88, 254,
            82, 212, 75, 124, 233, 228, 161, 19, 81, 110, 138, 101, 132,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 22,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 19,
                offset: 0,
            },
            Relocation {
                at: 27,
                width: 3,
                role: 21,
                offset: 0,
            },
            Relocation {
                at: 37,
                width: 3,
                role: 19,
                offset: 0,
            },
        ],
    },
    // constructor/part1
    Span {
        component: Component::Normal,
        start: 0x16c888,
        len: 46,
        digest: [
            186, 205, 117, 177, 129, 255, 219, 143, 224, 108, 91, 109, 145, 122, 177, 196, 9, 252,
            112, 220, 109, 150, 221, 92, 38, 44, 22, 154, 23, 191, 197, 9,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x53e2,
        len: 36,
        digest: [
            66, 94, 118, 27, 109, 221, 228, 59, 44, 101, 50, 110, 252, 254, 238, 104, 74, 86, 252,
            85, 168, 72, 30, 35, 162, 138, 222, 113, 188, 66, 246, 21,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x544a,
        len: 44,
        digest: [
            117, 61, 252, 239, 29, 153, 36, 186, 158, 127, 235, 32, 16, 30, 47, 16, 198, 229, 231,
            59, 221, 245, 122, 182, 142, 132, 54, 190, 97, 112, 205, 116,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 20,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x5520,
        len: 44,
        digest: [
            169, 201, 118, 241, 78, 188, 113, 48, 90, 211, 120, 142, 16, 123, 115, 140, 16, 1, 174,
            85, 174, 38, 109, 144, 104, 140, 115, 214, 243, 61, 253, 167,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 20,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x574a,
        len: 30,
        digest: [
            230, 231, 177, 39, 134, 255, 99, 154, 98, 37, 135, 118, 97, 203, 227, 145, 157, 237,
            140, 233, 235, 22, 169, 93, 100, 197, 192, 30, 214, 29, 227, 32,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x59b2,
        len: 142,
        digest: [
            194, 11, 15, 41, 105, 76, 109, 127, 161, 15, 42, 154, 192, 140, 216, 34, 53, 229, 10,
            228, 23, 217, 253, 77, 224, 62, 169, 233, 183, 200, 157, 234,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 32,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 31,
                offset: 0,
            },
            Relocation {
                at: 27,
                width: 3,
                role: 34,
                offset: 0,
            },
            Relocation {
                at: 37,
                width: 3,
                role: 36,
                offset: 0,
            },
            Relocation {
                at: 47,
                width: 3,
                role: 29,
                offset: 0,
            },
            Relocation {
                at: 57,
                width: 3,
                role: 37,
                offset: 0,
            },
            Relocation {
                at: 67,
                width: 3,
                role: 30,
                offset: 0,
            },
            Relocation {
                at: 77,
                width: 3,
                role: 35,
                offset: 0,
            },
            Relocation {
                at: 87,
                width: 3,
                role: 25,
                offset: 0,
            },
            Relocation {
                at: 97,
                width: 3,
                role: 26,
                offset: 0,
            },
            Relocation {
                at: 107,
                width: 3,
                role: 33,
                offset: 0,
            },
            Relocation {
                at: 117,
                width: 3,
                role: 27,
                offset: 0,
            },
            Relocation {
                at: 127,
                width: 3,
                role: 28,
                offset: 0,
            },
            Relocation {
                at: 137,
                width: 3,
                role: 38,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x6882,
        len: 44,
        digest: [
            138, 141, 32, 41, 234, 128, 59, 164, 170, 243, 214, 165, 188, 188, 142, 206, 48, 242,
            207, 14, 218, 169, 164, 187, 107, 126, 235, 177, 160, 54, 173, 9,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x6f48,
        len: 44,
        digest: [
            252, 207, 248, 0, 175, 66, 126, 35, 163, 157, 138, 154, 21, 17, 46, 153, 151, 78, 135,
            119, 246, 223, 170, 254, 144, 66, 182, 175, 233, 28, 181, 53,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x7066,
        len: 44,
        digest: [
            141, 85, 108, 123, 245, 243, 104, 167, 194, 149, 72, 238, 196, 96, 183, 205, 175, 185,
            68, 244, 208, 68, 99, 113, 238, 175, 49, 178, 127, 146, 129, 75,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x70da,
        len: 44,
        digest: [
            193, 98, 66, 183, 154, 222, 158, 86, 125, 18, 0, 98, 19, 8, 189, 95, 56, 113, 29, 193,
            220, 30, 203, 160, 141, 175, 252, 137, 1, 201, 178, 229,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x747c,
        len: 44,
        digest: [
            53, 148, 206, 127, 188, 222, 121, 135, 58, 79, 111, 27, 200, 246, 47, 78, 73, 228, 220,
            129, 4, 10, 22, 236, 73, 154, 187, 180, 233, 80, 32, 214,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x750a,
        len: 44,
        digest: [
            135, 249, 158, 202, 229, 138, 65, 53, 241, 59, 56, 171, 51, 151, 32, 92, 17, 201, 64,
            216, 67, 138, 189, 19, 52, 220, 197, 58, 228, 168, 243, 52,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x7572,
        len: 44,
        digest: [
            208, 106, 113, 198, 82, 13, 241, 20, 217, 99, 103, 215, 135, 76, 95, 120, 58, 238, 211,
            4, 104, 185, 237, 64, 136, 119, 99, 27, 9, 27, 198, 24,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x75ac,
        len: 50,
        digest: [
            178, 179, 203, 12, 126, 213, 180, 93, 142, 176, 225, 237, 23, 153, 63, 152, 151, 191,
            135, 53, 88, 154, 189, 29, 213, 227, 91, 100, 229, 183, 174, 142,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x766a,
        len: 44,
        digest: [
            100, 14, 182, 85, 24, 253, 95, 30, 19, 76, 101, 19, 202, 126, 233, 25, 75, 230, 99, 81,
            218, 42, 42, 86, 186, 134, 231, 249, 133, 69, 143, 185,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x76de,
        len: 44,
        digest: [
            114, 57, 167, 36, 137, 136, 54, 43, 52, 143, 213, 66, 46, 139, 45, 137, 100, 184, 187,
            146, 175, 180, 15, 173, 40, 62, 147, 20, 209, 238, 189, 141,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x7866,
        len: 44,
        digest: [
            128, 234, 113, 192, 132, 238, 195, 220, 163, 188, 92, 17, 128, 186, 232, 121, 102, 105,
            233, 59, 15, 19, 254, 127, 44, 37, 164, 51, 90, 187, 171, 237,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x7990,
        len: 44,
        digest: [
            15, 143, 37, 137, 177, 103, 96, 208, 236, 22, 139, 149, 13, 218, 69, 126, 73, 133, 251,
            21, 57, 159, 186, 125, 79, 139, 34, 102, 42, 126, 210, 118,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x7a1e,
        len: 44,
        digest: [
            251, 50, 192, 223, 141, 79, 149, 151, 236, 0, 77, 84, 13, 235, 56, 175, 156, 72, 112,
            120, 64, 244, 127, 193, 228, 224, 221, 52, 86, 23, 98, 44,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x7a86,
        len: 44,
        digest: [
            14, 214, 200, 89, 200, 64, 92, 205, 32, 206, 59, 41, 6, 250, 142, 95, 92, 229, 81, 233,
            22, 176, 233, 99, 129, 98, 209, 13, 75, 77, 73, 72,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 23,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13c0c,
        len: 12,
        digest: [
            85, 17, 92, 41, 247, 253, 106, 196, 93, 216, 118, 8, 195, 119, 117, 226, 39, 219, 237,
            103, 230, 206, 191, 139, 161, 163, 92, 26, 226, 219, 133, 167,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 113,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x1f296,
        len: 40,
        digest: [
            178, 125, 116, 41, 39, 240, 228, 186, 227, 185, 230, 156, 27, 95, 19, 6, 63, 62, 246,
            132, 63, 231, 182, 39, 30, 194, 27, 21, 157, 48, 9, 195,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x2f656,
        len: 996,
        digest: [
            0, 73, 76, 216, 207, 132, 120, 77, 192, 234, 151, 245, 49, 28, 98, 100, 179, 7, 5, 12,
            2, 142, 28, 69, 209, 27, 194, 213, 35, 216, 88, 131,
        ],
        relocations: &[
            Relocation {
                at: 335,
                width: 3,
                role: 42,
                offset: 0,
            },
            Relocation {
                at: 645,
                width: 3,
                role: 43,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x3039a,
        len: 40,
        digest: [
            29, 141, 128, 43, 253, 65, 156, 199, 102, 203, 180, 123, 177, 160, 210, 24, 174, 193,
            148, 15, 132, 178, 245, 193, 197, 164, 94, 234, 230, 62, 22, 26,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x3a650,
        len: 34,
        digest: [
            59, 188, 43, 136, 41, 187, 32, 254, 66, 66, 12, 210, 233, 124, 80, 14, 172, 172, 229,
            90, 16, 15, 207, 146, 206, 28, 176, 28, 187, 141, 239, 12,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x40054,
        len: 58,
        digest: [
            227, 142, 242, 191, 237, 191, 214, 53, 115, 53, 209, 3, 175, 147, 233, 234, 76, 149,
            217, 56, 42, 77, 24, 91, 182, 243, 150, 238, 108, 60, 221, 86,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x40158,
        len: 58,
        digest: [
            6, 65, 236, 249, 211, 90, 123, 45, 228, 152, 10, 14, 199, 4, 119, 69, 203, 222, 162,
            252, 41, 230, 192, 23, 208, 131, 179, 98, 162, 225, 237, 216,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x40394,
        len: 58,
        digest: [
            121, 234, 33, 231, 141, 1, 209, 247, 185, 127, 78, 12, 199, 57, 108, 104, 112, 190, 54,
            61, 245, 58, 96, 54, 197, 235, 3, 221, 122, 52, 175, 151,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x40490,
        len: 58,
        digest: [
            65, 87, 192, 178, 108, 155, 219, 75, 13, 153, 150, 218, 14, 170, 181, 135, 251, 73, 58,
            78, 85, 216, 231, 225, 132, 31, 228, 105, 20, 20, 4, 85,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x405cc,
        len: 58,
        digest: [
            222, 134, 255, 185, 135, 151, 165, 190, 52, 76, 96, 77, 154, 147, 100, 23, 120, 236,
            141, 199, 60, 255, 203, 217, 131, 54, 28, 169, 104, 210, 131, 179,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x40730,
        len: 58,
        digest: [
            1, 194, 10, 232, 144, 162, 88, 75, 78, 165, 23, 33, 95, 29, 169, 86, 30, 58, 254, 130,
            215, 126, 21, 176, 94, 252, 86, 12, 42, 87, 218, 170,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x4083c,
        len: 58,
        digest: [
            171, 239, 101, 14, 137, 93, 22, 194, 190, 44, 57, 109, 41, 209, 37, 236, 102, 75, 135,
            84, 108, 63, 63, 204, 211, 36, 92, 55, 22, 230, 46, 177,
        ],
        relocations: &[Relocation {
            at: 47,
            width: 3,
            role: 6,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x409ae,
        len: 30,
        digest: [
            244, 4, 85, 163, 72, 114, 111, 94, 168, 125, 226, 79, 92, 161, 212, 148, 96, 240, 150,
            171, 168, 159, 37, 80, 55, 181, 114, 239, 250, 239, 149, 60,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x40fc4,
        len: 82,
        digest: [
            2, 48, 200, 83, 152, 48, 136, 254, 240, 95, 220, 167, 117, 219, 83, 97, 244, 195, 205,
            106, 160, 131, 217, 148, 174, 120, 37, 221, 244, 28, 186, 81,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 44,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 45,
                offset: 0,
            },
            Relocation {
                at: 27,
                width: 3,
                role: 46,
                offset: 0,
            },
            Relocation {
                at: 37,
                width: 3,
                role: 47,
                offset: 0,
            },
            Relocation {
                at: 47,
                width: 3,
                role: 48,
                offset: 0,
            },
            Relocation {
                at: 57,
                width: 3,
                role: 49,
                offset: 0,
            },
            Relocation {
                at: 67,
                width: 3,
                role: 50,
                offset: 0,
            },
            Relocation {
                at: 77,
                width: 3,
                role: 51,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x41432,
        len: 12,
        digest: [
            2, 153, 66, 39, 170, 113, 199, 191, 209, 109, 116, 90, 201, 112, 52, 182, 117, 61, 9,
            253, 123, 152, 62, 237, 152, 231, 167, 48, 223, 226, 38, 83,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 113,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x4553c,
        len: 156,
        digest: [
            114, 48, 7, 155, 191, 33, 254, 137, 199, 30, 48, 246, 91, 2, 178, 148, 236, 71, 25, 86,
            33, 62, 133, 237, 1, 69, 160, 234, 48, 132, 151, 117,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x50404,
        len: 40,
        digest: [
            175, 186, 85, 242, 40, 118, 22, 73, 187, 148, 40, 62, 112, 142, 208, 112, 254, 111,
            137, 82, 114, 19, 89, 59, 231, 45, 33, 205, 201, 25, 26, 39,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x6b0fe,
        len: 22,
        digest: [
            167, 48, 135, 13, 160, 146, 243, 22, 192, 230, 118, 202, 9, 99, 152, 90, 33, 173, 49,
            160, 241, 77, 221, 38, 124, 143, 123, 205, 186, 155, 89, 154,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 113,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 113,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x8b362,
        len: 12,
        digest: [
            143, 58, 218, 16, 5, 140, 77, 254, 172, 90, 190, 4, 88, 255, 217, 135, 29, 221, 178,
            35, 201, 93, 14, 65, 43, 98, 81, 158, 200, 6, 8, 28,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 113,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x99bd8,
        len: 30,
        digest: [
            124, 104, 238, 128, 183, 244, 76, 79, 218, 20, 117, 85, 182, 178, 26, 163, 108, 219,
            245, 67, 47, 252, 127, 233, 222, 127, 41, 27, 4, 183, 67, 229,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9a508,
        len: 30,
        digest: [
            33, 101, 246, 51, 204, 152, 167, 180, 88, 232, 193, 9, 164, 213, 55, 77, 60, 30, 148,
            142, 49, 197, 81, 225, 168, 191, 134, 75, 185, 114, 163, 148,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9cc9c,
        len: 44,
        digest: [
            32, 105, 190, 37, 187, 151, 69, 250, 170, 40, 5, 2, 43, 111, 253, 191, 252, 24, 27,
            231, 53, 51, 203, 202, 188, 73, 184, 146, 110, 57, 60, 240,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9ce00,
        len: 46,
        digest: [
            181, 97, 212, 201, 192, 240, 181, 196, 213, 164, 211, 228, 87, 152, 227, 208, 26, 128,
            228, 123, 13, 199, 117, 120, 167, 122, 79, 136, 221, 51, 248, 78,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 62,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9cf36,
        len: 44,
        digest: [
            13, 75, 173, 144, 100, 129, 137, 61, 62, 128, 31, 166, 16, 1, 58, 227, 45, 203, 225,
            67, 165, 231, 202, 253, 142, 8, 75, 183, 48, 225, 226, 157,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9d26e,
        len: 30,
        digest: [
            232, 12, 101, 235, 61, 111, 222, 39, 75, 92, 144, 41, 152, 139, 85, 123, 112, 150, 126,
            240, 85, 93, 185, 204, 140, 255, 87, 193, 207, 64, 150, 93,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9dad0,
        len: 96,
        digest: [
            135, 128, 102, 76, 221, 226, 40, 245, 243, 123, 138, 87, 89, 165, 111, 80, 110, 201, 7,
            132, 164, 39, 34, 59, 118, 249, 113, 145, 73, 75, 210, 218,
        ],
        relocations: &[
            Relocation {
                at: 11,
                width: 3,
                role: 67,
                offset: 0,
            },
            Relocation {
                at: 37,
                width: 3,
                role: 70,
                offset: 0,
            },
            Relocation {
                at: 61,
                width: 3,
                role: 69,
                offset: 0,
            },
            Relocation {
                at: 79,
                width: 3,
                role: 61,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9db32,
        len: 44,
        digest: [
            3, 116, 14, 250, 210, 26, 186, 146, 226, 164, 42, 230, 43, 13, 210, 221, 65, 172, 127,
            245, 9, 158, 108, 84, 227, 134, 139, 234, 96, 9, 13, 172,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 68,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9db64,
        len: 44,
        digest: [
            81, 183, 20, 109, 203, 41, 159, 63, 23, 44, 224, 144, 190, 68, 193, 78, 101, 30, 82,
            77, 142, 25, 223, 137, 235, 39, 80, 90, 214, 100, 109, 137,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 68,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9dbcc,
        len: 44,
        digest: [
            243, 10, 168, 129, 89, 29, 149, 46, 113, 34, 174, 155, 147, 11, 78, 167, 75, 140, 179,
            236, 166, 138, 8, 238, 178, 137, 3, 228, 18, 113, 160, 108,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 63,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9df66,
        len: 76,
        digest: [
            194, 47, 111, 150, 247, 154, 149, 233, 111, 150, 188, 137, 81, 202, 75, 185, 242, 198,
            129, 18, 10, 113, 233, 216, 250, 238, 17, 123, 86, 114, 180, 146,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 63,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9e558,
        len: 52,
        digest: [
            182, 163, 48, 124, 168, 253, 65, 5, 29, 220, 9, 15, 26, 251, 7, 246, 37, 1, 31, 63,
            175, 236, 190, 43, 221, 234, 69, 235, 163, 4, 46, 247,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 62,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x9e8ba,
        len: 46,
        digest: [
            88, 179, 194, 246, 40, 141, 149, 112, 120, 219, 227, 161, 150, 186, 164, 133, 212, 119,
            81, 11, 229, 103, 120, 164, 163, 66, 111, 81, 175, 2, 151, 98,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 62,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xa1c22,
        len: 22,
        digest: [
            182, 120, 218, 144, 223, 203, 95, 144, 165, 207, 59, 109, 18, 63, 206, 189, 125, 197,
            94, 247, 81, 61, 7, 85, 35, 224, 120, 3, 219, 149, 43, 176,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 113,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 113,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xa6b5e,
        len: 30,
        digest: [
            7, 3, 130, 73, 210, 202, 115, 138, 62, 194, 213, 132, 130, 178, 98, 67, 211, 173, 48,
            225, 26, 208, 17, 98, 31, 205, 145, 252, 22, 242, 168, 141,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xa85dc,
        len: 18,
        digest: [
            115, 141, 160, 55, 104, 99, 120, 163, 171, 63, 241, 242, 80, 105, 234, 175, 37, 45,
            116, 49, 52, 118, 61, 174, 227, 246, 189, 132, 25, 141, 33, 116,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xa9316,
        len: 124,
        digest: [
            18, 67, 49, 230, 240, 174, 92, 64, 74, 255, 78, 71, 191, 86, 12, 208, 95, 61, 192, 83,
            134, 9, 78, 254, 17, 58, 33, 83, 76, 159, 98, 186,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbcc6e,
        len: 12,
        digest: [
            11, 250, 7, 116, 125, 63, 17, 43, 148, 117, 32, 192, 244, 68, 73, 203, 5, 195, 184,
            104, 225, 24, 184, 95, 11, 61, 81, 160, 137, 227, 128, 95,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 81,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbccbe,
        len: 12,
        digest: [
            23, 141, 70, 151, 149, 172, 242, 60, 198, 7, 236, 61, 244, 196, 76, 209, 65, 239, 40,
            129, 177, 47, 21, 135, 66, 71, 195, 24, 25, 88, 22, 176,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 79,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbd532,
        len: 104,
        digest: [
            9, 215, 237, 254, 156, 246, 126, 6, 94, 115, 230, 34, 255, 71, 151, 23, 102, 117, 175,
            121, 63, 3, 175, 14, 7, 79, 126, 164, 226, 234, 247, 116,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbd5ca,
        len: 16,
        digest: [
            183, 217, 24, 45, 223, 164, 211, 160, 62, 79, 6, 113, 196, 227, 183, 137, 244, 36, 119,
            78, 154, 3, 206, 83, 117, 48, 130, 71, 46, 204, 192, 150,
        ],
        relocations: &[Relocation {
            at: 11,
            width: 3,
            role: 77,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbd664,
        len: 36,
        digest: [
            131, 158, 203, 40, 246, 131, 112, 248, 20, 57, 7, 17, 38, 26, 152, 26, 137, 141, 42,
            130, 165, 87, 31, 62, 129, 200, 226, 195, 95, 187, 43, 153,
        ],
        relocations: &[Relocation {
            at: 25,
            width: 3,
            role: 78,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbd664,
        len: 44,
        digest: [
            115, 198, 49, 66, 253, 37, 126, 238, 228, 31, 52, 2, 238, 92, 190, 91, 232, 115, 41,
            124, 118, 62, 182, 181, 251, 140, 132, 209, 215, 10, 32, 131,
        ],
        relocations: &[Relocation {
            at: 25,
            width: 3,
            role: 78,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xbdd80,
        len: 62,
        digest: [
            181, 116, 234, 245, 244, 64, 49, 158, 221, 25, 221, 83, 83, 184, 240, 5, 96, 182, 23,
            39, 3, 95, 127, 235, 19, 191, 119, 177, 28, 245, 186, 19,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xca810,
        len: 22,
        digest: [
            109, 168, 230, 60, 210, 196, 113, 209, 167, 40, 12, 115, 233, 28, 19, 184, 232, 88, 3,
            164, 97, 221, 168, 194, 243, 55, 113, 212, 150, 29, 180, 120,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 113,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 113,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xd8dcc,
        len: 10,
        digest: [
            230, 195, 200, 70, 48, 123, 107, 187, 100, 231, 64, 54, 246, 238, 200, 4, 18, 165, 198,
            213, 27, 53, 20, 126, 4, 96, 182, 205, 176, 63, 158, 22,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xeb190,
        len: 60,
        digest: [
            79, 210, 119, 73, 198, 87, 196, 48, 183, 25, 60, 80, 118, 70, 75, 178, 53, 68, 145, 70,
            203, 77, 194, 218, 83, 74, 118, 242, 41, 198, 47, 171,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xec37a,
        len: 24,
        digest: [
            199, 29, 32, 51, 187, 175, 211, 254, 18, 142, 198, 220, 96, 28, 176, 58, 72, 25, 157,
            122, 78, 224, 139, 170, 14, 114, 73, 95, 45, 84, 121, 208,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 84,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xef972,
        len: 22,
        digest: [
            157, 62, 22, 100, 109, 227, 73, 51, 38, 251, 180, 214, 113, 113, 231, 127, 128, 228, 8,
            114, 110, 58, 123, 169, 9, 145, 135, 148, 174, 151, 170, 136,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xfb368,
        len: 88,
        digest: [
            198, 32, 65, 86, 194, 57, 141, 0, 144, 230, 198, 69, 130, 71, 88, 46, 95, 149, 248,
            125, 109, 131, 14, 43, 59, 60, 52, 237, 82, 131, 162, 48,
        ],
        relocations: &[
            Relocation {
                at: 29,
                width: 3,
                role: 122,
                offset: 0,
            },
            Relocation {
                at: 41,
                width: 3,
                role: 122,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xfbb8e,
        len: 36,
        digest: [
            211, 121, 124, 21, 209, 109, 113, 98, 210, 245, 14, 58, 63, 145, 9, 187, 43, 241, 171,
            115, 247, 187, 235, 177, 103, 237, 224, 204, 253, 227, 63, 233,
        ],
        relocations: &[Relocation {
            at: 29,
            width: 3,
            role: 124,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xfc560,
        len: 38,
        digest: [
            104, 202, 57, 70, 50, 214, 145, 76, 2, 141, 55, 62, 94, 151, 244, 142, 6, 222, 0, 43,
            167, 133, 111, 219, 9, 185, 140, 192, 130, 253, 51, 138,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 87,
                offset: 0,
            },
            Relocation {
                at: 27,
                width: 3,
                role: 8,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0xfd596,
        len: 22,
        digest: [
            196, 88, 190, 83, 37, 246, 108, 226, 184, 2, 245, 124, 26, 232, 189, 127, 178, 20, 197,
            159, 183, 57, 109, 222, 78, 225, 46, 183, 178, 42, 38, 130,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 113,
                offset: 0,
            },
            Relocation {
                at: 17,
                width: 3,
                role: 113,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x102e8e,
        len: 36,
        digest: [
            246, 16, 3, 167, 200, 12, 68, 142, 254, 230, 142, 235, 107, 71, 175, 222, 213, 4, 94,
            31, 193, 192, 8, 88, 132, 219, 146, 186, 147, 131, 146, 104,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x1075ec,
        len: 492,
        digest: [
            88, 84, 14, 242, 211, 170, 46, 131, 177, 50, 132, 95, 175, 31, 132, 160, 164, 73, 10,
            163, 217, 110, 117, 138, 234, 133, 233, 202, 206, 41, 54, 119,
        ],
        relocations: &[
            Relocation {
                at: 319,
                width: 3,
                role: 113,
                offset: 0,
            },
            Relocation {
                at: 427,
                width: 3,
                role: 91,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x10b74e,
        len: 12,
        digest: [
            127, 80, 115, 239, 88, 183, 201, 150, 25, 171, 40, 246, 100, 104, 86, 143, 14, 209, 75,
            146, 231, 129, 90, 91, 202, 29, 70, 114, 217, 115, 59, 20,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 113,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x111a6c,
        len: 10,
        digest: [
            160, 233, 37, 243, 66, 147, 223, 211, 70, 174, 127, 98, 219, 26, 20, 98, 237, 50, 7,
            194, 96, 180, 228, 124, 164, 213, 209, 195, 238, 149, 171, 94,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x1120bc,
        len: 10,
        digest: [
            88, 223, 176, 8, 111, 51, 4, 75, 202, 160, 161, 222, 4, 180, 24, 246, 244, 197, 147,
            54, 97, 65, 22, 244, 143, 0, 88, 244, 127, 74, 182, 219,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x1160ba,
        len: 10,
        digest: [
            227, 211, 136, 21, 141, 214, 45, 128, 101, 23, 128, 15, 59, 134, 112, 135, 11, 197, 29,
            5, 223, 223, 151, 239, 62, 249, 143, 195, 8, 238, 131, 197,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x1174ca,
        len: 10,
        digest: [
            30, 155, 237, 81, 66, 153, 12, 4, 69, 38, 219, 9, 123, 238, 75, 180, 27, 72, 226, 177,
            24, 182, 10, 6, 185, 203, 58, 220, 186, 39, 211, 27,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x11a35a,
        len: 32,
        digest: [
            49, 156, 0, 11, 6, 51, 104, 128, 149, 47, 134, 74, 112, 96, 8, 250, 116, 185, 71, 92,
            19, 54, 193, 111, 103, 15, 159, 74, 143, 64, 168, 173,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x11bf02,
        len: 30,
        digest: [
            7, 72, 126, 226, 243, 53, 240, 188, 33, 172, 147, 123, 5, 116, 50, 163, 19, 143, 21,
            61, 222, 51, 204, 167, 134, 140, 191, 155, 172, 188, 246, 228,
        ],
        relocations: &[Relocation {
            at: 25,
            width: 3,
            role: 98,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x120602,
        len: 12,
        digest: [
            179, 195, 3, 153, 126, 130, 227, 54, 206, 81, 154, 175, 74, 197, 214, 166, 235, 244,
            132, 161, 143, 129, 118, 179, 167, 153, 192, 191, 231, 1, 82, 75,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 120,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x120df6,
        len: 36,
        digest: [
            14, 196, 247, 137, 230, 168, 122, 155, 136, 157, 8, 196, 243, 215, 212, 226, 73, 126,
            67, 186, 146, 66, 88, 147, 78, 42, 243, 230, 168, 80, 34, 73,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x122a5a,
        len: 76,
        digest: [
            38, 43, 109, 138, 240, 220, 130, 158, 221, 128, 117, 158, 228, 56, 239, 112, 218, 251,
            194, 232, 28, 67, 112, 96, 161, 28, 204, 62, 252, 255, 233, 139,
        ],
        relocations: &[Relocation {
            at: 23,
            width: 3,
            role: 101,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x123c4c,
        len: 458,
        digest: [
            37, 11, 118, 212, 33, 34, 61, 183, 44, 213, 180, 39, 69, 211, 223, 212, 92, 119, 198,
            235, 148, 176, 35, 125, 103, 105, 33, 26, 118, 105, 57, 160,
        ],
        relocations: &[Relocation {
            at: 251,
            width: 3,
            role: 102,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x12577e,
        len: 10,
        digest: [
            122, 79, 167, 5, 186, 57, 18, 134, 8, 252, 107, 230, 18, 221, 184, 16, 131, 24, 136,
            82, 13, 187, 84, 226, 154, 12, 20, 176, 215, 103, 252, 163,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x12853a,
        len: 10,
        digest: [
            27, 24, 116, 94, 150, 193, 158, 22, 222, 57, 6, 206, 136, 130, 126, 170, 55, 189, 114,
            236, 116, 94, 164, 22, 76, 98, 188, 239, 195, 5, 249, 84,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x1312b6,
        len: 10,
        digest: [
            26, 114, 234, 62, 252, 116, 236, 133, 246, 217, 16, 17, 150, 68, 29, 250, 87, 87, 49,
            36, 240, 19, 28, 238, 245, 207, 107, 252, 32, 154, 189, 170,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x1312c0,
        len: 58,
        digest: [
            128, 229, 251, 39, 224, 116, 223, 79, 45, 100, 53, 141, 168, 174, 165, 239, 253, 164,
            214, 189, 162, 94, 216, 54, 141, 64, 126, 166, 98, 246, 76, 105,
        ],
        relocations: &[Relocation {
            at: 27,
            width: 3,
            role: 113,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x133dd6,
        len: 30,
        digest: [
            30, 54, 59, 113, 233, 111, 102, 16, 42, 61, 181, 154, 175, 188, 85, 159, 72, 251, 135,
            108, 58, 36, 234, 201, 133, 207, 130, 174, 232, 86, 106, 251,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13419e,
        len: 266,
        digest: [
            235, 217, 199, 12, 17, 230, 54, 137, 105, 187, 196, 251, 132, 250, 210, 5, 31, 52, 124,
            189, 31, 200, 117, 176, 157, 141, 240, 55, 126, 35, 74, 129,
        ],
        relocations: &[
            Relocation {
                at: 7,
                width: 3,
                role: 108,
                offset: 0,
            },
            Relocation {
                at: 31,
                width: 3,
                role: 108,
                offset: 0,
            },
            Relocation {
                at: 55,
                width: 3,
                role: 108,
                offset: 0,
            },
            Relocation {
                at: 79,
                width: 3,
                role: 108,
                offset: 0,
            },
            Relocation {
                at: 103,
                width: 3,
                role: 108,
                offset: 0,
            },
            Relocation {
                at: 127,
                width: 3,
                role: 108,
                offset: 0,
            },
            Relocation {
                at: 151,
                width: 3,
                role: 108,
                offset: 0,
            },
            Relocation {
                at: 175,
                width: 3,
                role: 108,
                offset: 0,
            },
            Relocation {
                at: 199,
                width: 3,
                role: 108,
                offset: 0,
            },
            Relocation {
                at: 223,
                width: 3,
                role: 108,
                offset: 0,
            },
            Relocation {
                at: 247,
                width: 3,
                role: 108,
                offset: 0,
            },
        ],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13c6d4,
        len: 10,
        digest: [
            120, 253, 198, 236, 125, 5, 208, 187, 124, 179, 27, 172, 77, 164, 191, 253, 60, 0, 32,
            189, 67, 158, 35, 104, 84, 198, 241, 202, 58, 34, 231, 200,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13de64,
        len: 12,
        digest: [
            83, 204, 51, 29, 179, 161, 38, 70, 252, 92, 29, 94, 70, 184, 154, 105, 244, 78, 85,
            148, 47, 209, 9, 116, 156, 68, 242, 79, 39, 153, 181, 33,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 113,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13e884,
        len: 10,
        digest: [
            172, 30, 127, 39, 227, 137, 163, 48, 8, 126, 58, 203, 134, 159, 217, 63, 215, 196, 181,
            176, 51, 112, 62, 255, 83, 57, 181, 60, 181, 59, 55, 53,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13e88e,
        len: 32,
        digest: [
            54, 49, 2, 21, 80, 248, 26, 216, 159, 101, 7, 226, 248, 218, 17, 183, 199, 165, 234,
            120, 77, 219, 28, 190, 112, 210, 248, 215, 121, 92, 112, 55,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13ed54,
        len: 10,
        digest: [
            131, 65, 99, 189, 244, 143, 144, 82, 194, 170, 235, 189, 49, 61, 213, 175, 17, 171, 94,
            32, 64, 62, 139, 47, 63, 223, 170, 193, 86, 156, 179, 72,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x13fac0,
        len: 32,
        digest: [
            69, 154, 231, 130, 250, 68, 144, 208, 32, 93, 13, 69, 56, 108, 239, 204, 84, 247, 7,
            31, 8, 188, 206, 217, 206, 46, 127, 113, 83, 99, 10, 161,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x142c4a,
        len: 10,
        digest: [
            117, 143, 95, 179, 239, 86, 188, 33, 144, 18, 135, 202, 26, 116, 59, 255, 11, 175, 175,
            189, 141, 32, 4, 243, 113, 5, 57, 223, 116, 76, 210, 219,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x143910,
        len: 4930,
        digest: [
            145, 30, 61, 251, 71, 45, 18, 236, 240, 77, 209, 206, 114, 220, 55, 72, 249, 87, 196,
            158, 90, 20, 8, 116, 165, 62, 221, 240, 242, 176, 43, 5,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x158f6a,
        len: 12,
        digest: [
            33, 146, 131, 151, 7, 4, 198, 25, 15, 84, 77, 29, 172, 189, 59, 114, 146, 127, 162, 4,
            50, 223, 40, 115, 81, 38, 66, 46, 127, 225, 180, 88,
        ],
        relocations: &[Relocation {
            at: 7,
            width: 3,
            role: 113,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x15cc4a,
        len: 44,
        digest: [
            165, 250, 82, 132, 253, 232, 100, 174, 148, 147, 110, 207, 92, 164, 27, 176, 54, 141,
            17, 253, 136, 123, 5, 217, 243, 105, 132, 12, 142, 78, 138, 81,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x169342,
        len: 28,
        digest: [
            68, 210, 163, 66, 181, 58, 73, 255, 155, 233, 75, 104, 240, 187, 245, 132, 199, 208,
            189, 118, 76, 55, 29, 178, 189, 117, 223, 149, 197, 252, 56, 123,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x16c888,
        len: 46,
        digest: [
            186, 205, 117, 177, 129, 255, 219, 143, 224, 108, 91, 109, 145, 122, 177, 196, 9, 252,
            112, 220, 109, 150, 221, 92, 38, 44, 22, 154, 23, 191, 197, 9,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x16c8b6,
        len: 10,
        digest: [
            74, 233, 209, 57, 132, 77, 120, 52, 61, 144, 59, 173, 123, 190, 144, 131, 148, 199,
            114, 210, 24, 191, 20, 6, 8, 204, 183, 141, 134, 169, 0, 146,
        ],
        relocations: &[Relocation {
            at: 5,
            width: 3,
            role: 8,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x16c906,
        len: 286,
        digest: [
            162, 12, 71, 39, 136, 104, 27, 31, 14, 211, 248, 122, 154, 67, 207, 248, 153, 43, 54,
            84, 243, 213, 213, 87, 162, 253, 194, 76, 157, 196, 215, 32,
        ],
        relocations: &[Relocation {
            at: 77,
            width: 3,
            role: 8,
            offset: 50,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x16ca24,
        len: 70,
        digest: [
            208, 84, 112, 139, 115, 124, 197, 77, 144, 106, 122, 127, 56, 66, 255, 161, 73, 98,
            199, 100, 71, 6, 222, 113, 33, 146, 73, 244, 76, 132, 109, 147,
        ],
        relocations: &[Relocation {
            at: 57,
            width: 3,
            role: 123,
            offset: 0,
        }],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x16cada,
        len: 30,
        digest: [
            13, 47, 29, 81, 236, 247, 220, 65, 151, 235, 28, 205, 180, 85, 52, 88, 125, 246, 29,
            100, 137, 51, 97, 248, 98, 155, 36, 240, 94, 75, 191, 213,
        ],
        relocations: &[],
    },
    // constructor/part0
    Span {
        component: Component::Normal,
        start: 0x16caf8,
        len: 50,
        digest: [
            102, 201, 134, 246, 216, 61, 57, 227, 82, 118, 113, 54, 142, 160, 0, 19, 196, 150, 1,
            109, 50, 173, 81, 11, 181, 240, 103, 188, 30, 255, 195, 161,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x4585a4/part0
    Span {
        component: Component::Normal,
        start: 0x48b06,
        len: 1882,
        digest: [
            235, 105, 63, 11, 251, 9, 254, 240, 41, 112, 207, 101, 120, 195, 46, 4, 191, 75, 232,
            123, 242, 6, 201, 223, 14, 59, 35, 226, 65, 72, 14, 179,
        ],
        relocations: &[
            Relocation {
                at: 421,
                width: 3,
                role: 127,
                offset: 856,
            },
            Relocation {
                at: 605,
                width: 3,
                role: 127,
                offset: 856,
            },
            Relocation {
                at: 1305,
                width: 3,
                role: 127,
                offset: 1864,
            },
            Relocation {
                at: 1503,
                width: 3,
                role: 127,
                offset: 1864,
            },
        ],
    },
    // ordinary-prefix/0x458d16/part0
    Span {
        component: Component::Normal,
        start: 0x49278,
        len: 64,
        digest: [
            54, 73, 98, 131, 108, 181, 60, 60, 131, 207, 216, 141, 158, 167, 249, 54, 85, 150, 234,
            186, 170, 181, 229, 164, 136, 64, 28, 38, 251, 60, 32, 41,
        ],
        relocations: &[
            Relocation {
                at: 23,
                width: 3,
                role: 120,
                offset: 0,
            },
            Relocation {
                at: 33,
                width: 3,
                role: 140,
                offset: 0,
            },
        ],
    },
    // ordinary-prefix/0x458e92/part0
    Span {
        component: Component::Normal,
        start: 0x493f4,
        len: 52,
        digest: [
            237, 79, 162, 22, 117, 97, 193, 47, 153, 192, 197, 0, 102, 87, 161, 207, 15, 222, 228,
            198, 200, 231, 15, 226, 131, 9, 108, 124, 52, 113, 184, 43,
        ],
        relocations: &[
            Relocation {
                at: 23,
                width: 3,
                role: 120,
                offset: 0,
            },
            Relocation {
                at: 33,
                width: 3,
                role: 140,
                offset: 0,
            },
            Relocation {
                at: 41,
                width: 3,
                role: 132,
                offset: 0,
            },
            Relocation {
                at: 45,
                width: 3,
                role: 131,
                offset: 0,
            },
        ],
    },
    // ordinary-prefix/0x458ec6/part0
    Span {
        component: Component::Normal,
        start: 0x49428,
        len: 128,
        digest: [
            71, 116, 199, 91, 28, 99, 25, 10, 225, 92, 76, 188, 23, 41, 49, 222, 235, 203, 95, 5,
            212, 24, 54, 169, 215, 51, 74, 255, 63, 198, 21, 252,
        ],
        relocations: &[
            Relocation {
                at: 27,
                width: 3,
                role: 128,
                offset: 0,
            },
            Relocation {
                at: 93,
                width: 3,
                role: 138,
                offset: 0,
            },
            Relocation {
                at: 99,
                width: 3,
                role: 134,
                offset: 0,
            },
            Relocation {
                at: 107,
                width: 3,
                role: 135,
                offset: 0,
            },
        ],
    },
    // ordinary-prefix/0x458f46/part0
    Span {
        component: Component::Normal,
        start: 0x494a8,
        len: 172,
        digest: [
            241, 166, 146, 125, 163, 104, 114, 179, 158, 184, 110, 20, 161, 93, 41, 207, 188, 250,
            174, 248, 59, 109, 105, 54, 164, 234, 6, 250, 193, 119, 232, 133,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x458ff2/part0
    Span {
        component: Component::Normal,
        start: 0x49554,
        len: 288,
        digest: [
            167, 20, 180, 183, 97, 230, 11, 162, 128, 217, 29, 31, 39, 239, 145, 195, 194, 93, 223,
            74, 210, 229, 243, 226, 180, 224, 99, 119, 139, 119, 30, 230,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x459112/part0
    Span {
        component: Component::Normal,
        start: 0x49674,
        len: 270,
        digest: [
            20, 79, 85, 211, 78, 65, 44, 70, 235, 130, 94, 16, 182, 41, 26, 91, 110, 188, 116, 183,
            129, 177, 28, 59, 242, 206, 10, 0, 78, 202, 241, 48,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x45aef4/part0
    Span {
        component: Component::Normal,
        start: 0x4b456,
        len: 132,
        digest: [
            119, 30, 128, 146, 60, 216, 173, 243, 128, 84, 159, 76, 148, 226, 89, 40, 152, 29, 101,
            91, 246, 89, 209, 113, 55, 35, 44, 119, 55, 85, 255, 6,
        ],
        relocations: &[
            Relocation {
                at: 53,
                width: 3,
                role: 136,
                offset: 0,
            },
            Relocation {
                at: 123,
                width: 3,
                role: 137,
                offset: 0,
            },
        ],
    },
    // ordinary-prefix/0x45af78/part0
    Span {
        component: Component::Normal,
        start: 0x4b4da,
        len: 190,
        digest: [
            157, 179, 225, 96, 77, 249, 177, 202, 145, 184, 198, 17, 0, 255, 125, 134, 168, 1, 232,
            39, 179, 57, 89, 37, 113, 182, 138, 85, 73, 101, 116, 22,
        ],
        relocations: &[Relocation {
            at: 93,
            width: 3,
            role: 128,
            offset: 0,
        }],
    },
    // ordinary-prefix/0x45b514/part0
    Span {
        component: Component::Normal,
        start: 0x4ba76,
        len: 8,
        digest: [
            226, 170, 78, 229, 31, 183, 159, 234, 165, 15, 201, 176, 166, 240, 37, 85, 195, 117,
            167, 189, 147, 183, 204, 60, 196, 207, 247, 227, 29, 95, 30, 47,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x45b51c/part0
    Span {
        component: Component::Normal,
        start: 0x4ba7e,
        len: 16,
        digest: [
            13, 97, 46, 143, 15, 202, 95, 31, 68, 255, 132, 174, 142, 73, 240, 143, 179, 123, 54,
            100, 87, 135, 181, 249, 21, 175, 231, 191, 145, 152, 214, 66,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x45b52c/part0
    Span {
        component: Component::Normal,
        start: 0x4ba8e,
        len: 84,
        digest: [
            240, 137, 235, 212, 120, 141, 122, 19, 163, 120, 121, 169, 239, 212, 153, 114, 108,
            191, 143, 129, 188, 9, 220, 29, 176, 188, 139, 225, 10, 71, 158, 114,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x578894/part0
    Span {
        component: Component::Normal,
        start: 0x169342,
        len: 28,
        digest: [
            68, 210, 163, 66, 181, 58, 73, 255, 155, 233, 75, 104, 240, 187, 245, 132, 199, 208,
            189, 118, 76, 55, 29, 178, 189, 117, 223, 149, 197, 252, 56, 123,
        ],
        relocations: &[],
    },
    // ordinary-prefix/0x5788de/part0
    Span {
        component: Component::Normal,
        start: 0x16938c,
        len: 20,
        digest: [
            129, 49, 240, 60, 184, 221, 89, 197, 173, 216, 230, 54, 111, 222, 131, 141, 101, 159,
            125, 11, 58, 172, 58, 63, 93, 251, 15, 103, 18, 162, 31, 13,
        ],
        relocations: &[],
    },
    // kernel-entry/0x400276/part0
    Span {
        component: Component::Kernel,
        start: 0x288,
        len: 416,
        digest: [
            205, 27, 140, 159, 23, 188, 213, 121, 93, 139, 114, 199, 239, 51, 168, 109, 126, 227,
            205, 63, 25, 215, 98, 175, 137, 37, 21, 73, 25, 119, 46, 173,
        ],
        relocations: &[Relocation {
            at: 5,
            width: 3,
            role: 144,
            offset: 0,
        }],
    },
    // kernel-entry/0x40554e/part0
    Span {
        component: Component::Kernel,
        start: 0x572c,
        len: 188,
        digest: [
            85, 249, 64, 80, 240, 164, 119, 183, 43, 191, 106, 108, 109, 238, 42, 220, 129, 97,
            212, 76, 119, 168, 189, 110, 123, 137, 95, 90, 32, 119, 177, 10,
        ],
        relocations: &[],
    },
    // kernel-entry/0x40490c/part0
    Span {
        component: Component::Kernel,
        start: 0x49e8,
        len: 6,
        digest: [
            94, 187, 145, 244, 80, 44, 237, 146, 165, 8, 98, 84, 219, 129, 8, 133, 113, 7, 42, 216,
            48, 148, 179, 134, 143, 107, 245, 36, 210, 152, 104, 58,
        ],
        relocations: &[Relocation {
            at: 1,
            width: 3,
            role: 0,
            offset: 0,
        }],
    },
    // kernel-entry/0x4060f6/part0
    Span {
        component: Component::Kernel,
        start: 0x62d4,
        len: 46,
        digest: [
            238, 133, 123, 174, 199, 166, 59, 225, 70, 244, 142, 15, 182, 169, 1, 56, 149, 198,
            171, 99, 97, 239, 165, 223, 107, 53, 163, 199, 123, 136, 115, 203,
        ],
        relocations: &[],
    },
    // query-diagnostic/549532/part0
    Span {
        component: Component::Normal,
        start: 0x139532,
        len: 8,
        digest: [
            33, 33, 87, 29, 56, 220, 116, 150, 231, 32, 121, 108, 72, 128, 4, 98, 85, 222, 218,
            198, 181, 96, 195, 245, 247, 195, 99, 176, 219, 157, 153, 93,
        ],
        relocations: &[],
    },
    // query-diagnostic/549622/part0
    Span {
        component: Component::Normal,
        start: 0x139622,
        len: 78,
        digest: [
            47, 253, 179, 242, 23, 229, 82, 204, 225, 22, 7, 157, 86, 13, 42, 51, 219, 229, 173,
            180, 62, 204, 176, 37, 42, 179, 180, 52, 205, 82, 48, 209,
        ],
        relocations: &[
            Relocation {
                at: 31,
                width: 3,
                role: 145,
                offset: 0,
            },
            Relocation {
                at: 69,
                width: 3,
                role: 147,
                offset: 0,
            },
        ],
    },
    // query-diagnostic/54a00a/part0
    Span {
        component: Component::Normal,
        start: 0x13a00a,
        len: 574,
        digest: [
            65, 80, 225, 14, 139, 183, 232, 195, 54, 195, 73, 208, 126, 31, 226, 145, 156, 238, 13,
            63, 163, 38, 3, 53, 127, 185, 173, 59, 0, 216, 24, 61,
        ],
        relocations: &[
            Relocation {
                at: 179,
                width: 3,
                role: 149,
                offset: 0,
            },
            Relocation {
                at: 255,
                width: 3,
                role: 148,
                offset: 0,
            },
            Relocation {
                at: 269,
                width: 3,
                role: 150,
                offset: 0,
            },
            Relocation {
                at: 467,
                width: 3,
                role: 149,
                offset: 0,
            },
        ],
    },
    // query-diagnostic/54a248/part0
    Span {
        component: Component::Normal,
        start: 0x13a248,
        len: 158,
        digest: [
            41, 168, 240, 24, 8, 104, 169, 64, 103, 201, 241, 116, 195, 125, 244, 63, 59, 153, 59,
            78, 253, 61, 138, 101, 215, 77, 48, 124, 23, 5, 126, 172,
        ],
        relocations: &[
            Relocation {
                at: 9,
                width: 3,
                role: 149,
                offset: 0,
            },
            Relocation {
                at: 57,
                width: 3,
                role: 150,
                offset: 0,
            },
        ],
    },
    // query-diagnostic/54a2e6/part0
    Span {
        component: Component::Normal,
        start: 0x13a2e6,
        len: 26,
        digest: [
            201, 208, 251, 57, 240, 22, 114, 210, 52, 11, 12, 246, 127, 220, 25, 238, 212, 251, 96,
            22, 178, 51, 138, 18, 74, 116, 84, 78, 194, 77, 150, 233,
        ],
        relocations: &[],
    },
    // query-diagnostic/54e8f2/part0
    Span {
        component: Component::Normal,
        start: 0x13e8f2,
        len: 10,
        digest: [
            183, 59, 153, 172, 27, 73, 141, 209, 185, 140, 149, 26, 107, 221, 86, 161, 86, 36, 137,
            227, 135, 244, 44, 196, 161, 172, 97, 40, 126, 29, 103, 150,
        ],
        relocations: &[],
    },
    // normal-query
    Span {
        component: Component::Normal,
        start: 0x16c4ee,
        len: 118,
        digest: [
            136, 184, 182, 6, 101, 212, 2, 149, 38, 53, 120, 92, 160, 137, 213, 221, 112, 2, 38,
            200, 46, 225, 226, 175, 138, 27, 0, 126, 61, 234, 119, 242,
        ],
        relocations: &[Relocation {
            at: 61,
            width: 3,
            role: 146,
            offset: 0,
        }],
    },
    // normal-builder
    Span {
        component: Component::Normal,
        start: 0x16c592,
        len: 120,
        digest: [
            46, 53, 32, 112, 90, 141, 81, 205, 161, 120, 91, 14, 4, 223, 163, 224, 71, 200, 205,
            163, 219, 18, 204, 38, 239, 212, 189, 47, 59, 218, 75, 158,
        ],
        relocations: &[],
    },
    // diagnostic-fixed-copy-source
    Span {
        component: Component::Normal,
        start: 0x191550,
        len: 8,
        digest: [
            124, 127, 215, 239, 0, 243, 83, 224, 121, 116, 107, 175, 219, 248, 228, 161, 16, 36,
            23, 94, 194, 77, 30, 175, 236, 194, 63, 164, 246, 38, 97, 36,
        ],
        relocations: &[],
    },
    // kernel-clear-wrapper
    Span {
        component: Component::Normal,
        start: 0x47c62,
        len: 6,
        digest: [
            94, 187, 145, 244, 80, 44, 237, 146, 165, 8, 98, 84, 219, 129, 8, 133, 113, 7, 42, 216,
            48, 148, 179, 134, 143, 107, 245, 36, 210, 152, 104, 58,
        ],
        relocations: &[Relocation {
            at: 1,
            width: 3,
            role: 165,
            offset: 0,
        }],
    },
    // predispatch-port-leaf
    Span {
        component: Component::Normal,
        start: 0xdd9f8,
        len: 12,
        digest: [
            223, 3, 16, 153, 42, 201, 73, 208, 61, 190, 169, 44, 232, 138, 5, 58, 233, 67, 13, 160,
            180, 58, 177, 104, 175, 36, 192, 147, 245, 167, 8, 221,
        ],
        relocations: &[],
    },
    // bank-adjacent-call-prefix
    Span {
        component: Component::Normal,
        start: 0x4f338,
        len: 12,
        digest: [
            34, 220, 68, 55, 188, 193, 191, 134, 106, 171, 240, 44, 95, 15, 147, 31, 6, 211, 124,
            132, 156, 225, 40, 186, 92, 114, 115, 216, 79, 82, 59, 224,
        ],
        relocations: &[
            Relocation {
                at: 5,
                width: 3,
                role: 157,
                offset: 0,
            },
            Relocation {
                at: 9,
                width: 3,
                role: 158,
                offset: 0,
            },
        ],
    },
    // bank-capacity-producer
    Span {
        component: Component::Normal,
        start: 0x13cdf2,
        len: 50,
        digest: [
            62, 220, 197, 57, 13, 214, 204, 240, 168, 76, 32, 79, 228, 25, 145, 60, 151, 40, 76,
            112, 134, 31, 1, 182, 103, 90, 117, 107, 120, 117, 47, 209,
        ],
        relocations: &[],
    },
    // bank-validator
    Span {
        component: Component::Normal,
        start: 0x13ce24,
        len: 156,
        digest: [
            226, 25, 143, 62, 79, 110, 158, 126, 141, 190, 191, 24, 38, 129, 178, 79, 110, 90, 36,
            90, 75, 43, 6, 183, 221, 35, 244, 53, 61, 205, 48, 67,
        ],
        relocations: &[Relocation {
            at: 139,
            width: 3,
            role: 159,
            offset: 0,
        }],
    },
    // bank-loader-helper
    Span {
        component: Component::Normal,
        start: 0x9f58e,
        len: 18,
        digest: [
            163, 36, 161, 252, 238, 20, 239, 156, 231, 55, 55, 16, 89, 192, 198, 114, 180, 246, 12,
            24, 182, 83, 26, 180, 20, 103, 66, 237, 127, 133, 164, 177,
        ],
        relocations: &[
            Relocation {
                at: 3,
                width: 3,
                role: 160,
                offset: 0,
            },
            Relocation {
                at: 9,
                width: 3,
                role: 161,
                offset: 0,
            },
        ],
    },
    // bank-loader-wrapper/2
    Span {
        component: Component::Normal,
        start: 0x47c20,
        len: 6,
        digest: [
            209, 190, 47, 118, 27, 60, 193, 182, 112, 115, 147, 217, 98, 56, 33, 197, 188, 171, 18,
            74, 120, 195, 224, 237, 2, 14, 235, 60, 242, 239, 224, 52,
        ],
        relocations: &[],
    },
    // bank-loader-wrapper/8
    Span {
        component: Component::Normal,
        start: 0x47c26,
        len: 6,
        digest: [
            229, 212, 181, 246, 50, 90, 77, 39, 70, 223, 163, 183, 155, 78, 120, 173, 139, 253, 14,
            49, 25, 166, 157, 38, 35, 54, 119, 72, 170, 188, 165, 8,
        ],
        relocations: &[],
    },
    // warm-entry-flag
    Span {
        component: Component::Kernel,
        start: 0x100,
        len: 8,
        digest: [
            224, 122, 191, 21, 1, 251, 255, 9, 87, 97, 69, 17, 238, 181, 100, 196, 163, 43, 108,
            115, 92, 14, 56, 244, 246, 209, 188, 13, 28, 40, 217, 121,
        ],
        relocations: &[],
    },
    // kernel-successful-root
    Span {
        component: Component::Kernel,
        start: 0x108,
        len: 354,
        digest: [
            136, 5, 197, 147, 73, 27, 223, 177, 246, 0, 171, 175, 120, 50, 158, 236, 245, 144, 201,
            43, 59, 94, 161, 66, 41, 212, 14, 22, 229, 12, 55, 107,
        ],
        relocations: &[
            Relocation {
                at: 73,
                width: 3,
                role: 174,
                offset: 0,
            },
            Relocation {
                at: 111,
                width: 3,
                role: 174,
                offset: 0,
            },
            Relocation {
                at: 135,
                width: 3,
                role: 141,
                offset: 0,
            },
            Relocation {
                at: 159,
                width: 3,
                role: 142,
                offset: 0,
            },
            Relocation {
                at: 179,
                width: 3,
                role: 163,
                offset: 354,
            },
            Relocation {
                at: 209,
                width: 3,
                role: 163,
                offset: 354,
            },
            Relocation {
                at: 345,
                width: 3,
                role: 143,
                offset: 0,
            },
        ],
    },
    // kernel-early-copied-block
    Span {
        component: Component::Kernel,
        start: 0x4d8,
        len: 786,
        digest: [
            51, 228, 196, 176, 204, 200, 159, 194, 254, 39, 176, 15, 202, 179, 2, 248, 163, 169,
            181, 182, 34, 139, 131, 233, 237, 237, 246, 193, 200, 187, 8, 37,
        ],
        relocations: &[],
    },
    // kernel-clear-trampoline
    Span {
        component: Component::Kernel,
        start: 0xa5c,
        len: 4,
        digest: [
            169, 98, 201, 154, 224, 102, 100, 21, 231, 142, 251, 150, 186, 177, 3, 159, 64, 74,
            190, 159, 155, 232, 142, 49, 126, 231, 228, 196, 115, 223, 170, 50,
        ],
        relocations: &[Relocation {
            at: 1,
            width: 3,
            role: 166,
            offset: 0,
        }],
    },
    // kernel-clear-body
    Span {
        component: Component::Kernel,
        start: 0x4c4,
        len: 20,
        digest: [
            201, 206, 50, 4, 196, 217, 28, 182, 232, 165, 143, 5, 111, 252, 15, 65, 15, 94, 255,
            23, 13, 247, 132, 177, 219, 90, 168, 207, 243, 86, 146, 165,
        ],
        relocations: &[Relocation {
            at: 15,
            width: 3,
            role: 174,
            offset: 0,
        }],
    },
    // kernel-startup-runtime-entry
    Span {
        component: Component::Kernel,
        start: 0xb6f4,
        len: 26,
        digest: [
            233, 55, 81, 200, 123, 206, 10, 193, 244, 29, 132, 151, 32, 223, 190, 131, 121, 226,
            254, 194, 217, 153, 61, 141, 77, 136, 202, 141, 137, 147, 40, 166,
        ],
        relocations: &[
            Relocation {
                at: 17,
                width: 3,
                role: 171,
                offset: 0,
            },
            Relocation {
                at: 21,
                width: 3,
                role: 168,
                offset: 0,
            },
        ],
    },
    // kernel-zero-return
    Span {
        component: Component::Kernel,
        start: 0xb600,
        len: 4,
        digest: [
            38, 69, 1, 199, 28, 47, 210, 193, 124, 121, 195, 7, 83, 131, 13, 237, 155, 168, 179,
            172, 225, 68, 249, 60, 44, 57, 152, 165, 27, 82, 9, 166,
        ],
        relocations: &[],
    },
    // kernel-ccr-helper
    Span {
        component: Component::Kernel,
        start: 0xb9c2,
        len: 20,
        digest: [
            16, 24, 71, 232, 105, 23, 248, 115, 91, 103, 88, 49, 41, 239, 163, 238, 194, 12, 177,
            230, 19, 20, 80, 98, 143, 111, 151, 31, 50, 134, 67, 30,
        ],
        relocations: &[],
    },
    // kernel-pool-init
    Span {
        component: Component::Kernel,
        start: 0xccdc,
        len: 18,
        digest: [
            11, 116, 53, 119, 174, 189, 109, 158, 132, 255, 114, 142, 120, 255, 247, 128, 67, 197,
            176, 17, 172, 164, 11, 238, 49, 143, 26, 135, 134, 95, 243, 231,
        ],
        relocations: &[],
    },
    // kernel-runtime-init
    Span {
        component: Component::Kernel,
        start: 0xba56,
        len: 1370,
        digest: [
            251, 171, 119, 214, 92, 82, 241, 232, 134, 153, 88, 89, 209, 151, 5, 169, 198, 13, 27,
            103, 64, 191, 158, 165, 160, 0, 84, 168, 50, 31, 227, 132,
        ],
        relocations: &[
            Relocation {
                at: 13,
                width: 3,
                role: 169,
                offset: 0,
            },
            Relocation {
                at: 149,
                width: 3,
                role: 170,
                offset: 0,
            },
            Relocation {
                at: 183,
                width: 3,
                role: 170,
                offset: 0,
            },
            Relocation {
                at: 219,
                width: 3,
                role: 170,
                offset: 0,
            },
        ],
    },
    // kernel-runtime-descriptor
    Span {
        component: Component::Kernel,
        start: 0xff2a,
        len: 124,
        digest: [
            15, 155, 34, 131, 206, 167, 187, 113, 62, 161, 127, 31, 99, 19, 79, 123, 176, 90, 132,
            126, 86, 188, 149, 109, 104, 165, 75, 57, 90, 101, 14, 234,
        ],
        relocations: &[],
    },
    // kernel-copy-wrapper
    Span {
        component: Component::Kernel,
        start: 0x5efe,
        len: 24,
        digest: [
            22, 51, 165, 244, 48, 233, 184, 219, 9, 215, 36, 105, 153, 187, 19, 151, 148, 188, 44,
            7, 112, 154, 202, 220, 162, 51, 202, 186, 65, 2, 192, 168,
        ],
        relocations: &[Relocation {
            at: 15,
            width: 3,
            role: 175,
            offset: 0,
        }],
    },
    // kernel-clear-wrapper
    Span {
        component: Component::Kernel,
        start: 0x5f16,
        len: 18,
        digest: [
            47, 189, 110, 221, 49, 130, 252, 242, 163, 69, 58, 22, 192, 109, 126, 213, 218, 129,
            53, 85, 172, 28, 114, 122, 28, 191, 186, 210, 17, 111, 33, 224,
        ],
        relocations: &[Relocation {
            at: 11,
            width: 3,
            role: 176,
            offset: 0,
        }],
    },
    // kernel-copy-adapter
    Span {
        component: Component::Kernel,
        start: 0x6a9c,
        len: 30,
        digest: [
            13, 47, 29, 81, 236, 247, 220, 65, 151, 235, 28, 205, 180, 85, 52, 88, 125, 246, 29,
            100, 137, 51, 97, 248, 98, 155, 36, 240, 94, 75, 191, 213,
        ],
        relocations: &[],
    },
    // kernel-fill-body
    Span {
        component: Component::Kernel,
        start: 0x6aba,
        len: 50,
        digest: [
            102, 201, 134, 246, 216, 61, 57, 227, 82, 118, 113, 54, 142, 160, 0, 19, 196, 150, 1,
            109, 50, 173, 81, 11, 181, 240, 103, 188, 30, 255, 195, 161,
        ],
        relocations: &[],
    },
    // kernel-initial-data0
    Span {
        component: Component::Kernel,
        start: 0xca2,
        len: 168,
        digest: [
            2, 62, 146, 118, 102, 44, 31, 19, 109, 71, 75, 209, 29, 175, 122, 33, 167, 64, 112,
            253, 54, 13, 61, 8, 66, 165, 178, 231, 160, 65, 102, 39,
        ],
        relocations: &[],
    },
    // kernel-initial-data1
    Span {
        component: Component::Kernel,
        start: 0x6918,
        len: 24,
        digest: [
            128, 98, 137, 30, 149, 93, 227, 181, 157, 23, 220, 111, 1, 35, 102, 166, 174, 242, 59,
            217, 236, 155, 56, 112, 88, 119, 11, 80, 113, 24, 180, 117,
        ],
        relocations: &[],
    },
    // kernel-initial-data2
    Span {
        component: Component::Kernel,
        start: 0x6302,
        len: 16,
        digest: [
            148, 73, 239, 104, 115, 211, 98, 57, 15, 234, 248, 205, 80, 179, 148, 142, 254, 211,
            174, 127, 203, 31, 74, 217, 107, 22, 73, 108, 73, 66, 29, 218,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_query
    Span {
        component: Component::Kernel,
        start: 0x66e,
        len: 64,
        digest: [
            0, 132, 22, 205, 205, 5, 22, 64, 216, 170, 146, 220, 168, 63, 115, 89, 166, 9, 118,
            233, 2, 192, 31, 127, 109, 16, 165, 98, 46, 59, 148, 191,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_builder
    Span {
        component: Component::Kernel,
        start: 0x6dc,
        len: 120,
        digest: [
            46, 53, 32, 112, 90, 141, 81, 205, 161, 120, 91, 14, 4, 223, 163, 224, 71, 200, 205,
            163, 219, 18, 204, 38, 239, 212, 189, 47, 59, 218, 75, 158,
        ],
        relocations: &[],
    },
    // exact-comparison/normal_builder
    Span {
        component: Component::Normal,
        start: 0x16c592,
        len: 120,
        digest: [
            46, 53, 32, 112, 90, 141, 81, 205, 161, 120, 91, 14, 4, 223, 163, 224, 71, 200, 205,
            163, 219, 18, 204, 38, 239, 212, 189, 47, 59, 218, 75, 158,
        ],
        relocations: &[],
    },
    // exact-comparison/normal_query_prefix
    Span {
        component: Component::Normal,
        start: 0x16c4ee,
        len: 20,
        digest: [
            37, 38, 219, 31, 18, 81, 57, 240, 16, 213, 190, 129, 156, 159, 46, 113, 124, 51, 244,
            187, 115, 212, 195, 8, 185, 152, 139, 70, 143, 17, 131, 83,
        ],
        relocations: &[],
    },
    // exact-comparison/normal_query_tail
    Span {
        component: Component::Normal,
        start: 0x16c52e,
        len: 54,
        digest: [
            38, 19, 168, 241, 100, 117, 47, 39, 204, 144, 121, 117, 67, 9, 38, 135, 85, 84, 64,
            129, 186, 139, 179, 211, 243, 116, 32, 109, 136, 24, 44, 0,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_zero_return
    Span {
        component: Component::Kernel,
        start: 0xb600,
        len: 4,
        digest: [
            38, 69, 1, 199, 28, 47, 210, 193, 124, 121, 195, 7, 83, 131, 13, 237, 155, 168, 179,
            172, 225, 68, 249, 60, 44, 57, 152, 165, 27, 82, 9, 166,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_runtime_init
    Span {
        component: Component::Kernel,
        start: 0xba56,
        len: 1370,
        digest: [
            144, 131, 168, 56, 27, 239, 155, 179, 234, 217, 206, 55, 228, 185, 17, 110, 82, 129,
            12, 37, 239, 44, 214, 98, 153, 59, 245, 0, 184, 35, 55, 10,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_pool_init
    Span {
        component: Component::Kernel,
        start: 0xccdc,
        len: 18,
        digest: [
            11, 116, 53, 119, 174, 189, 109, 158, 132, 255, 114, 142, 120, 255, 247, 128, 67, 197,
            176, 17, 172, 164, 11, 238, 49, 143, 26, 135, 134, 95, 243, 231,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_runtime_parameters
    Span {
        component: Component::Kernel,
        start: 0xff2a,
        len: 124,
        digest: [
            15, 155, 34, 131, 206, 167, 187, 113, 62, 161, 127, 31, 99, 19, 79, 123, 176, 90, 132,
            126, 86, 188, 149, 109, 104, 165, 75, 57, 90, 101, 14, 234,
        ],
        relocations: &[],
    },
    // exact-comparison/kernel_native_memset
    Span {
        component: Component::Kernel,
        start: 0x6aba,
        len: 50,
        digest: [
            102, 201, 134, 246, 216, 61, 57, 227, 82, 118, 113, 54, 142, 160, 0, 19, 196, 150, 1,
            109, 50, 173, 81, 11, 181, 240, 103, 188, 30, 255, 195, 161,
        ],
        relocations: &[],
    },
];
pub(super) const FORMS: &[Form] = &[
    Form {
        spans: ROLES_0,
        kernel_descriptor: 0x63aa,
        compares_generation: false,
    },
    Form {
        spans: ROLES_1,
        kernel_descriptor: 0x6588,
        compares_generation: true,
    },
];
