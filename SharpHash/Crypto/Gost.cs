///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019  Mbadiwe Nnaemeka Ronald
/// Github Repository <https://github.com/ron4fun/SharpHash>
///
/// The contents of this file are subject to the
/// Mozilla Public License Version 2.0 (the "License");
/// you may not use this file except in
/// compliance with the License. You may obtain a copy of the License
/// at https://www.mozilla.org/en-US/MPL/2.0/
///
/// Software distributed under the License is distributed on an "AS IS"
/// basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
/// the License for the specific language governing rights and
/// limitations under the License.
///
/// Acknowledgements:
///
/// Thanks to Ugochukwu Mmaduekwe (https://github.com/Xor-el) for his creative
/// development of this library in Pascal/Delphi (https://github.com/Xor-el/HashLib4Pascal).
///
/// Also, I will like to thank Udezue Chukwunwike (https://github.com/IzarchTech) for
/// his contributions to the growth and development of this library.
///
////////////////////////////////////////////////////////////////////////

using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    internal sealed class Gost : BlockHash, ICryptoNotBuildIn, ITransformBlock
    {
        private UInt32[] state, hash;

        private static UInt32[] sbox1 = new UInt32[256];
        private static UInt32[] sbox2 = new UInt32[256];
        private static UInt32[] sbox3 = new UInt32[256];
        private static UInt32[] sbox4 = new UInt32[256];

        static Gost()
        {
            UInt32 ax, bx, cx, dx;

            UInt32[][] sbox = new UInt32[][] {
                new UInt32[] { 4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3 },
                new UInt32[] { 14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9 },
                new UInt32[] { 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11 },
                new UInt32[] { 7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3 },
                new UInt32[] { 6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2 },
                new UInt32[] { 4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14 },
                new UInt32[] { 13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12 },
                new UInt32[] { 1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12 }
            };

            Int32 i = 0;
            for (Int32 a = 0; a < 16; a++)
            {
                ax = sbox[1][a] << 15;
                bx = sbox[3][a] << 23;
                cx = sbox[5][a];
                cx = Bits.RotateRight32(cx, 1);
                dx = sbox[7][a] << 7;

                for (Int32 b = 0; b < 16; b++)
                {
                    sbox1[i] = ax | (sbox[0][b] << 11);
                    sbox2[i] = bx | (sbox[2][b] << 19);
                    sbox3[i] = cx | (sbox[4][b] << 27);
                    sbox4[i] = dx | (sbox[6][b] << 3);
                    i++;
                } // end for
            } // end for
        } // end static cctr

        public Gost()
            : base(32, 32)
        {
            state = new UInt32[8];
            hash = new UInt32[8];
        } // end constructor

        public override IHash Clone()
        {
            Gost HashInstance = new Gost();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.state = new UInt32[state.Length];
            Utils.Utils.memcopy(ref HashInstance.state, state, state.Length);

            HashInstance.hash = new UInt32[hash.Length];
            Utils.Utils.memcopy(ref HashInstance.hash, hash, hash.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override unsafe void Initialize()
        {
            Utils.Utils.memset(ref state, 0);
            Utils.Utils.memset(ref hash, 0);

            base.Initialize();
        } // end function Initialize

        protected override unsafe byte[] GetResult()
        {
            byte[] result = new byte[8 * sizeof(UInt32)];

            fixed (UInt32* hashPtr = hash)
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.le32_copy((IntPtr)hashPtr, 0, (IntPtr)resultPtr, 0,
                        result.Length);
                }
            }

            return result;
        } // end function GetResult

        protected override void Finish()
        {
            UInt64 bits = processed_bytes * 8;

            if (buffer.Position > 0)
            {
                byte[] pad = new byte[32 - buffer.Position];
                TransformBytes(pad, 0, 32 - buffer.Position);
            } // end if

            UInt32[] length = new UInt32[8];
            length[0] = (UInt32)bits;
            length[1] = (UInt32)(bits >> 32);

            Compress(length);

            Compress(state);
        } // end function Finish

        protected override unsafe void TransformBlock(IntPtr a_data,
                Int32 a_data_length, Int32 a_index)
        {
            UInt32 c, a, b;
            UInt32[] m = new UInt32[8], data = new UInt32[8];

            fixed (UInt32* dataPtr = data)
            {
                c = 0;
                Converters.le32_copy(a_data, a_index, (IntPtr)dataPtr, 0, 32);

                for (Int32 i = 0; i < 8; i++)
                {
                    a = data[i];
                    m[i] = a;
                    b = state[i];
                    c = a + c + state[i];
                    state[i] = c;

                    if ((c < a) || (c < b))
                        c = 1;
                    else
                        c = 0;
                } // end for

                Compress(m);

                Utils.Utils.memset(ref data, 0);
                Utils.Utils.memset(ref m, 0);
            }
        } // end function TransformBlock

        private void Compress(UInt32[] a_m)
        {
            UInt32 u0, u1, u2, u3, u4, u5, u6, u7, v0, v1, v2, v3, v4, v5, v6, v7, w0, w1, w2,
            w3, w4, w5, w6, w7, key0, key1, key2, key3, key4, key5, key6, key7, r, l, t;

            UInt32[] s = new UInt32[8];

            u0 = hash[0];
            u1 = hash[1];
            u2 = hash[2];
            u3 = hash[3];
            u4 = hash[4];
            u5 = hash[5];
            u6 = hash[6];
            u7 = hash[7];

            v0 = a_m[0];
            v1 = a_m[1];
            v2 = a_m[2];
            v3 = a_m[3];
            v4 = a_m[4];
            v5 = a_m[5];
            v6 = a_m[6];
            v7 = a_m[7];

            Int32 i = 0;
            while (i < 8)
            {
                w0 = u0 ^ v0;
                w1 = u1 ^ v1;
                w2 = u2 ^ v2;
                w3 = u3 ^ v3;
                w4 = u4 ^ v4;
                w5 = u5 ^ v5;
                w6 = u6 ^ v6;
                w7 = u7 ^ v7;

                key0 = (UInt32)((byte)(w0)) | ((UInt32)((byte)(w2)) << 8) |
                    ((UInt32)((byte)(w4)) << 16) | ((UInt32)((byte)(w6)) << 24);
                key1 = (UInt32)((byte)(w0 >> 8)) | (w2 & 0x0000FF00) |
                    ((w4 & 0x0000FF00) << 8) | ((w6 & 0x0000FF00) << 16);
                key2 = (UInt32)((byte)(w0 >> 16)) | ((w2 & 0x00FF0000) >> 8) |
                    (w4 & 0x00FF0000) | ((w6 & 0x00FF0000) << 8);
                key3 = (w0 >> 24) | ((w2 & 0xFF000000) >> 16) |
                    ((w4 & 0xFF000000) >> 8) | (w6 & 0xFF000000);
                key4 = (UInt32)((byte)(w1)) | ((w3 & 0x000000FF) << 8) |
                    ((w5 & 0x000000FF) << 16) | ((w7 & 0x000000FF) << 24);
                key5 = (UInt32)((byte)(w1 >> 8)) | (w3 & 0x0000FF00) |
                    ((w5 & 0x0000FF00) << 8) | ((w7 & 0x0000FF00) << 16);
                key6 = (UInt32)((byte)(w1 >> 16)) | ((w3 & 0x00FF0000) >> 8) |
                    (w5 & 0x00FF0000) | ((w7 & 0x00FF0000) << 8);
                key7 = (w1 >> 24) | ((w3 & 0xFF000000) >> 16) |
                    ((w5 & 0xFF000000) >> 8) | (w7 & 0xFF000000);

                r = hash[i];
                l = hash[i + 1];

                t = key0 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key1 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key2 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key3 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key4 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key5 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key6 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key7 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key0 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key1 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key2 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key3 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key4 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key5 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key6 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key7 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key0 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key1 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key2 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key3 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key4 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key5 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key6 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key7 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key7 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key6 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key5 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key4 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key3 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key2 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key1 + r;
                l = l ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);
                t = key0 + l;
                r = r ^ (sbox1[(byte)(t)] ^ sbox2[(byte)(t >> 8)] ^ sbox3
                    [(byte)(t >> 16)] ^ sbox4[t >> 24]);

                t = r;
                r = l;
                l = t;

                s[i] = r;
                s[i + 1] = l;

                if (i == 6)
                    break;

                l = u0 ^ u2;
                r = u1 ^ u3;
                u0 = u2;
                u1 = u3;
                u2 = u4;
                u3 = u5;
                u4 = u6;
                u5 = u7;
                u6 = l;
                u7 = r;

                if (i == 2)
                {
                    u0 = u0 ^ 0xFF00FF00;
                    u1 = u1 ^ 0xFF00FF00;
                    u2 = u2 ^ 0x00FF00FF;
                    u3 = u3 ^ 0x00FF00FF;
                    u4 = u4 ^ 0x00FFFF00;
                    u5 = u5 ^ 0xFF0000FF;
                    u6 = u6 ^ 0x000000FF;
                    u7 = u7 ^ 0xFF00FFFF;
                } // end if

                l = v0;
                r = v2;
                v0 = v4;
                v2 = v6;
                v4 = l ^ r;
                v6 = v0 ^ r;
                l = v1;
                r = v3;
                v1 = v5;
                v3 = v7;
                v5 = l ^ r;
                v7 = v1 ^ r;

                i += 2;
            } // end while

            u0 = a_m[0] ^ s[6];
            u1 = a_m[1] ^ s[7];
            u2 = a_m[2] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xFFFF)
                ^ (s[1] & 0xFFFF) ^ (s[1] >> 16) ^ (s[2] << 16)
                ^ s[6] ^ (s[6] << 16) ^ (s[7] & 0xFFFF0000) ^ (s[7] >> 16);
            u3 = a_m[3] ^ (s[0] & 0xFFFF) ^ (s[0] << 16) ^ (s[1] & 0xFFFF)
                ^ (s[1] << 16) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16)
                ^ (s[3] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16)
                ^ (s[7] & 0xFFFF) ^ (s[7] << 16) ^ (s[7] >> 16);
            u4 = a_m[4] ^ (s[0] & 0xFFFF0000) ^ (s[0] << 16) ^ (s[0] >> 16)
                ^ (s[1] & 0xFFFF0000) ^ (s[1] >> 16) ^ (s[2] << 16)
                ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16)
                ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xFFFF) ^ (s[7] << 16)
                ^ (s[7] >> 16);
            u5 = a_m[5] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xFFFF0000)
                ^ (s[1] & 0xFFFF) ^ s[2] ^ (s[2] >> 16) ^ (s[3] << 16)
                ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16)
                ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xFFFF0000)
                ^ (s[7] << 16) ^ (s[7] >> 16);
            u6 = a_m[6] ^ s[0] ^ (s[1] >> 16) ^ (s[2] << 16)
                ^ s[3] ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[4] >> 16)
                ^ (s[5] << 16) ^ (s[5] >> 16) ^ s[6] ^ (s[6] << 16)
                ^ (s[6] >> 16) ^ (s[7] << 16);
            u7 = a_m[7] ^ (s[0] & 0xFFFF0000) ^ (s[0] << 16) ^ (s[1] & 0xFFFF)
                ^ (s[1] << 16) ^ (s[2] >> 16) ^ (s[3] << 16)
                ^ s[4] ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16)
                ^ (s[6] >> 16) ^ (s[7] & 0xFFFF) ^ (s[7] << 16) ^ (s[7] >> 16);

            v0 = hash[0] ^ (u1 << 16) ^ (u0 >> 16);
            v1 = hash[1] ^ (u2 << 16) ^ (u1 >> 16);
            v2 = hash[2] ^ (u3 << 16) ^ (u2 >> 16);
            v3 = hash[3] ^ (u4 << 16) ^ (u3 >> 16);
            v4 = hash[4] ^ (u5 << 16) ^ (u4 >> 16);
            v5 = hash[5] ^ (u6 << 16) ^ (u5 >> 16);
            v6 = hash[6] ^ (u7 << 16) ^ (u6 >> 16);
            v7 = hash[7] ^ (u0 & 0xFFFF0000) ^ (u0 << 16) ^ (u7 >> 16)
                ^ (u1 & 0xFFFF0000) ^ (u1 << 16) ^ (u6 << 16)
                ^ (u7 & 0xFFFF0000);

            hash[0] = (v0 & 0xFFFF0000) ^ (v0 << 16) ^ (v0 >> 16)
                ^ (v1 >> 16) ^ (v1 & 0xFFFF0000) ^ (v2 << 16) ^ (v3 >> 16)
                ^ (v4 << 16) ^ (v5 >> 16) ^ v5 ^ (v6 >> 16) ^ (v7 << 16)
                ^ (v7 >> 16) ^ (v7 & 0xFFFF);
            hash[1] = (v0 << 16) ^ (v0 >> 16) ^ (v0 & 0xFFFF0000)
                ^ (v1 & 0xFFFF) ^ v2 ^ (v2 >> 16) ^ (v3 << 16) ^ (v4 >> 16)
                ^ (v5 << 16) ^ (v6 << 16) ^ v6 ^ (v7 & 0xFFFF0000)
                ^ (v7 >> 16);
            hash[2] = (v0 & 0xFFFF) ^ (v0 << 16) ^ (v1 << 16) ^ (v1 >> 16)
                ^ (v1 & 0xFFFF0000) ^ (v2 << 16) ^ (v3 >> 16)
                ^ v3 ^ (v4 << 16) ^ (v5 >> 16) ^ v6 ^ (v6 >> 16)
                ^ (v7 & 0xFFFF) ^ (v7 << 16) ^ (v7 >> 16);
            hash[3] = (v0 << 16) ^ (v0 >> 16) ^ (v0 & 0xFFFF0000)
                ^ (v1 & 0xFFFF0000) ^ (v1 >> 16) ^ (v2 << 16) ^ (v2 >> 16)
                ^ v2 ^ (v3 << 16) ^ (v4 >> 16) ^ v4 ^ (v5 << 16)
                ^ (v6 << 16) ^ (v7 & 0xFFFF) ^ (v7 >> 16);
            hash[4] = (v0 >> 16) ^ (v1 << 16) ^ v1 ^ (v2 >> 16)
                ^ v2 ^ (v3 << 16) ^ (v3 >> 16) ^ v3 ^ (v4 << 16)
                ^ (v5 >> 16) ^ v5 ^ (v6 << 16) ^ (v6 >> 16) ^ (v7 << 16);
            hash[5] = (v0 << 16) ^ (v0 & 0xFFFF0000) ^ (v1 << 16)
                ^ (v1 >> 16) ^ (v1 & 0xFFFF0000) ^ (v2 << 16)
                ^ v2 ^ (v3 >> 16) ^ v3 ^ (v4 << 16) ^ (v4 >> 16)
                ^ v4 ^ (v5 << 16) ^ (v6 << 16) ^ (v6 >> 16)
                ^ v6 ^ (v7 << 16) ^ (v7 >> 16) ^ (v7 & 0xFFFF0000);
            hash[6] = v0 ^ v2 ^ (v2 >> 16) ^ v3 ^ (v3 << 16)
                ^ v4 ^ (v4 >> 16) ^ (v5 << 16) ^ (v5 >> 16)
                ^ v5 ^ (v6 << 16) ^ (v6 >> 16) ^ v6 ^ (v7 << 16) ^ v7;
            hash[7] = v0 ^ (v0 >> 16) ^ (v1 << 16) ^ (v1 >> 16)
                ^ (v2 << 16) ^ (v3 >> 16) ^ v3 ^ (v4 << 16)
                ^ v4 ^ (v5 >> 16) ^ v5 ^ (v6 << 16) ^ (v6 >> 16)
                ^ (v7 << 16) ^ v7;
        } // end function GPT
    } // end class Gost
}