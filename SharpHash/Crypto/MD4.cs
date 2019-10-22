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

using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    internal sealed class MD4 : MDBase, ITransformBlock
    {
        private UInt32[] data = null;

        public MD4()
            : base(4, 16)
        {
            data = new UInt32[16];
        } // end constructor

        public override IHash Clone()
        {
            MD4 HashInstance = new MD4();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.state = new UInt32[state.Length];
            Utils.Utils.memcopy(ref HashInstance.state, state, state.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        protected override unsafe void TransformBlock(IntPtr a_data,
                Int32 a_data_length, Int32 a_index)
        {
            UInt32 a, b, c, d;

            fixed (UInt32* dPtr = data)
            {
                Converters.le32_copy(a_data, a_index, (IntPtr)dPtr, 0, 64);
            }

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];

            a = a + (data[0] + ((b & c) | ((~b) & d)));
            a = Bits.RotateLeft32(a, 3);
            d = d + (data[1] + ((a & b) | ((~a) & c)));
            d = Bits.RotateLeft32(d, 7);
            c = c + (data[2] + ((d & a) | ((~d) & b)));
            c = Bits.RotateLeft32(c, 11);
            b = b + (data[3] + ((c & d) | ((~c) & a)));
            b = Bits.RotateLeft32(b, 19);
            a = a + (data[4] + ((b & c) | ((~b) & d)));
            a = Bits.RotateLeft32(a, 3);
            d = d + (data[5] + ((a & b) | ((~a) & c)));
            d = Bits.RotateLeft32(d, 7);
            c = c + (data[6] + ((d & a) | ((~d) & b)));
            c = Bits.RotateLeft32(c, 11);
            b = b + (data[7] + ((c & d) | ((~c) & a)));
            b = Bits.RotateLeft32(b, 19);
            a = a + (data[8] + ((b & c) | ((~b) & d)));
            a = Bits.RotateLeft32(a, 3);
            d = d + (data[9] + ((a & b) | ((~a) & c)));
            d = Bits.RotateLeft32(d, 7);
            c = c + (data[10] + ((d & a) | ((~d) & b)));
            c = Bits.RotateLeft32(c, 11);
            b = b + (data[11] + ((c & d) | ((~c) & a)));
            b = Bits.RotateLeft32(b, 19);
            a = a + (data[12] + ((b & c) | ((~b) & d)));
            a = Bits.RotateLeft32(a, 3);
            d = d + (data[13] + ((a & b) | ((~a) & c)));
            d = Bits.RotateLeft32(d, 7);
            c = c + (data[14] + ((d & a) | ((~d) & b)));
            c = Bits.RotateLeft32(c, 11);
            b = b + (data[15] + ((c & d) | ((~c) & a)));
            b = Bits.RotateLeft32(b, 19);

            a = a + (data[0] + C2 + ((b & (c | d)) | (c & d)));
            a = Bits.RotateLeft32(a, 3);
            d = d + (data[4] + C2 + ((a & (b | c)) | (b & c)));
            d = Bits.RotateLeft32(d, 5);
            c = c + (data[8] + C2 + ((d & (a | b)) | (a & b)));
            c = Bits.RotateLeft32(c, 9);
            b = b + (data[12] + C2 + ((c & (d | a)) | (d & a)));
            b = Bits.RotateLeft32(b, 13);
            a = a + (data[1] + C2 + ((b & (c | d)) | (c & d)));
            a = Bits.RotateLeft32(a, 3);
            d = d + (data[5] + C2 + ((a & (b | c)) | (b & c)));
            d = Bits.RotateLeft32(d, 5);
            c = c + (data[9] + C2 + ((d & (a | b)) | (a & b)));
            c = Bits.RotateLeft32(c, 9);
            b = b + (data[13] + C2 + ((c & (d | a)) | (d & a)));
            b = Bits.RotateLeft32(b, 13);
            a = a + (data[2] + C2 + ((b & (c | d)) | (c & d)));
            a = Bits.RotateLeft32(a, 3);
            d = d + (data[6] + C2 + ((a & (b | c)) | (b & c)));
            d = Bits.RotateLeft32(d, 5);
            c = c + (data[10] + C2 + ((d & (a | b)) | (a & b)));
            c = Bits.RotateLeft32(c, 9);
            b = b + (data[14] + C2 + ((c & (d | a)) | (d & a)));
            b = Bits.RotateLeft32(b, 13);
            a = a + (data[3] + C2 + ((b & (c | d)) | (c & d)));
            a = Bits.RotateLeft32(a, 3);
            d = d + (data[7] + C2 + ((a & (b | c)) | (b & c)));
            d = Bits.RotateLeft32(d, 5);
            c = c + (data[11] + C2 + ((d & (a | b)) | (a & b)));
            c = Bits.RotateLeft32(c, 9);
            b = b + (data[15] + C2 + ((c & (d | a)) | (d & a)));
            b = Bits.RotateLeft32(b, 13);

            a = a + (data[0] + C4 + (b ^ c ^ d));
            a = Bits.RotateLeft32(a, 3);
            d = d + (data[8] + C4 + (a ^ b ^ c));
            d = Bits.RotateLeft32(d, 9);
            c = c + (data[4] + C4 + (d ^ a ^ b));
            c = Bits.RotateLeft32(c, 11);
            b = b + (data[12] + C4 + (c ^ d ^ a));
            b = Bits.RotateLeft32(b, 15);
            a = a + (data[2] + C4 + (b ^ c ^ d));
            a = Bits.RotateLeft32(a, 3);
            d = d + (data[10] + C4 + (a ^ b ^ c));
            d = Bits.RotateLeft32(d, 9);
            c = c + (data[6] + C4 + (d ^ a ^ b));
            c = Bits.RotateLeft32(c, 11);
            b = b + (data[14] + C4 + (c ^ d ^ a));
            b = Bits.RotateLeft32(b, 15);
            a = a + (data[1] + C4 + (b ^ c ^ d));
            a = Bits.RotateLeft32(a, 3);
            d = d + (data[9] + C4 + (a ^ b ^ c));
            d = Bits.RotateLeft32(d, 9);
            c = c + (data[5] + C4 + (d ^ a ^ b));
            c = Bits.RotateLeft32(c, 11);
            b = b + (data[13] + C4 + (c ^ d ^ a));
            b = Bits.RotateLeft32(b, 15);
            a = a + (data[3] + C4 + (b ^ c ^ d));
            a = Bits.RotateLeft32(a, 3);
            d = d + (data[11] + C4 + (a ^ b ^ c));
            d = Bits.RotateLeft32(d, 9);
            c = c + (data[7] + C4 + (d ^ a ^ b));
            c = Bits.RotateLeft32(c, 11);
            b = b + (data[15] + C4 + (c ^ d ^ a));
            b = Bits.RotateLeft32(b, 15);

            state[0] = state[0] + a;
            state[1] = state[1] + b;
            state[2] = state[2] + c;
            state[3] = state[3] + d;

            Utils.Utils.memset(ref data, 0);
        } // end function TransformBlock
    } // end class MD4
}