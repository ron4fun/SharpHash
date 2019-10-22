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
    internal sealed class HAS160 : BlockHash, ICryptoNotBuildIn, ITransformBlock
    {
        private UInt32[] hash = null;
        private UInt32[] data = null;

        private static readonly Int32[] rot = new Int32[] { 5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13 };
        private static readonly Int32[] tor = new Int32[] { 27, 21, 25, 17, 26, 19, 24, 18, 25, 20, 23, 21, 24, 17, 26, 20, 23, 18, 27, 19 };

        private static readonly Int32[] index = new Int32[] { 18, 0, 1, 2, 3, 19, 4, 5, 6, 7, 16, 8,
                                    9, 10, 11, 17, 12, 13, 14, 15, 18, 3, 6, 9, 12, 19, 15, 2, 5, 8, 16, 11,
                                    14, 1, 4, 17, 7, 10, 13, 0, 18, 12, 5, 14, 7, 19, 0, 9, 2, 11, 16, 4, 13,
                                    6, 15, 17, 8, 1, 10, 3, 18, 7, 2, 13, 8, 19, 3, 14, 9, 4, 16, 15, 10, 5,
                                    0, 17, 11, 6, 1, 12 };

        public HAS160()
            : base(20, 64)
        {
            hash = new UInt32[5];
            data = new UInt32[20];
        } // end constructor

        public override IHash Clone()
        {
            HAS160 HashInstance = new HAS160();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.hash = new UInt32[hash.Length];
            Utils.Utils.memcopy(ref HashInstance.hash, hash, hash.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override unsafe void Initialize()
        {
            hash[0] = 0x67452301;
            hash[1] = 0xEFCDAB89;
            hash[2] = 0x98BADCFE;
            hash[3] = 0x10325476;
            hash[4] = 0xC3D2E1F0;

            base.Initialize();
        } // end function Initialize

        protected override unsafe byte[] GetResult()
        {
            byte[] result = new byte[5 * sizeof(UInt32)];

            fixed (UInt32* statePtr = hash)
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.le32_copy((IntPtr)statePtr, 0, (IntPtr)resultPtr, 0,
                        result.Length);
                }
            }

            return result;
        } // end function GetResult

        protected override void Finish()
        {
            Int32 pad_index;

            UInt64 bits = processed_bytes * 8;

            pad_index = buffer.Position < 56 ? 56 - buffer.Position : 120 - buffer.Position;

            byte[] pad = new byte[pad_index + 8];

            pad[0] = 0x80;

            bits = Converters.le2me_64(bits);

            Converters.ReadUInt64AsBytesLE(bits, ref pad, pad_index);

            pad_index = pad_index + 8;

            TransformBytes(pad, 0, pad_index);
        } // end function Finish

        protected override unsafe void TransformBlock(IntPtr a_data,
                Int32 a_data_length, Int32 a_index)
        {
            UInt32 A, B, C, D, E, T;

            fixed (UInt32* dataPtr = data)
            {
                A = hash[0];
                B = hash[1];
                C = hash[2];
                D = hash[3];
                E = hash[4];

                Converters.le32_copy(a_data, a_index, (IntPtr)dataPtr, 0, 64);

                data[16] = data[0] ^ data[1] ^ data[2] ^ data[3];
                data[17] = data[4] ^ data[5] ^ data[6] ^ data[7];
                data[18] = data[8] ^ data[9] ^ data[10] ^ data[11];
                data[19] = data[12] ^ data[13] ^ data[14] ^ data[15];

                UInt32 r = 0;
                while (r < 20)
                {
                    T = data[index[r]] + (A << rot[r] | A >> tor[r]) + ((B & C) | (~B & D)) + E;
                    E = D;
                    D = C;
                    C = B << 10 | B >> 22;
                    B = A;
                    A = T;
                    r += 1;
                } // end while

                data[16] = data[3] ^ data[6] ^ data[9] ^ data[12];
                data[17] = data[2] ^ data[5] ^ data[8] ^ data[15];
                data[18] = data[1] ^ data[4] ^ data[11] ^ data[14];
                data[19] = data[0] ^ data[7] ^ data[10] ^ data[13];

                r = 20;
                while (r < 40)
                {
                    T = data[index[r]] + 0x5A827999 + (A << rot[r - 20] | A >> tor[r - 20]) + (B ^ C ^ D) + E;
                    E = D;
                    D = C;
                    C = B << 17 | B >> 15;
                    B = A;
                    A = T;
                    r += 1;
                } // end while

                data[16] = data[5] ^ data[7] ^ data[12] ^ data[14];
                data[17] = data[0] ^ data[2] ^ data[9] ^ data[11];
                data[18] = data[4] ^ data[6] ^ data[13] ^ data[15];
                data[19] = data[1] ^ data[3] ^ data[8] ^ data[10];

                r = 40;
                while (r < 60)
                {
                    T = data[index[r]] + 0x6ED9EBA1 + (A << rot[r - 40] | A >> tor[r - 40]) + (C ^ (B | ~D)) + E;
                    E = D;
                    D = C;
                    C = B << 25 | B >> 7;
                    B = A;
                    A = T;
                    r += 1;
                } // end while

                data[16] = data[2] ^ data[7] ^ data[8] ^ data[13];
                data[17] = data[3] ^ data[4] ^ data[9] ^ data[14];
                data[18] = data[0] ^ data[5] ^ data[10] ^ data[15];
                data[19] = data[1] ^ data[6] ^ data[11] ^ data[12];

                r = 60;
                while (r < 80)
                {
                    T = data[index[r]] + 0x8F1BBCDC + (A << rot[r - 60] | A >> tor[r - 60]) + (B ^ C ^ D) + E;
                    E = D;
                    D = C;
                    C = B << 30 | B >> 2;
                    B = A;
                    A = T;
                    r += 1;
                } // end while

                hash[0] = hash[0] + A;
                hash[1] = hash[1] + B;
                hash[2] = hash[2] + C;
                hash[3] = hash[3] + D;
                hash[4] = hash[4] + E;

                Utils.Utils.memset((IntPtr)dataPtr, 0, data.Length * sizeof(UInt32));
            }
        } // end function TransformBlock
    } // end class HAS160
}