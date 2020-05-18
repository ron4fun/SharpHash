///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019 - 2020  Mbadiwe Nnaemeka Ronald
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
    internal sealed class RIPEMD256 : MDBase, ITransformBlock
    {
        private UInt32[] data = null;

        public RIPEMD256()
            : base(8, 32)
        {
            data = new UInt32[16];
        } // end constructor

        public override IHash Clone()
        {
            RIPEMD256 HashInstance = new RIPEMD256();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.state = state.DeepCopy();

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override void Initialize()
        {
            state[4] = 0x76543210;
            state[5] = 0xFEDCBA98;
            state[6] = 0x89ABCDEF;
            state[7] = 0x01234567;

            base.Initialize();
        } // end function Initialize

        protected override unsafe void TransformBlock(IntPtr a_data,
                Int32 a_data_length, Int32 a_index)
        {
            UInt32 a, b, c, d, aa, bb, cc, dd;

            fixed (UInt32* dPtr = data)
            {
                Converters.le32_copy(a_data, a_index, (IntPtr)dPtr, 0, 64);
            }

            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            aa = state[4];
            bb = state[5];
            cc = state[6];
            dd = state[7];

            a = a + (data[0] + (b ^ c ^ d));
            a = Bits.RotateLeft32(a, 11);
            d = d + (data[1] + (a ^ b ^ c));
            d = Bits.RotateLeft32(d, 14);
            c = c + (data[2] + (d ^ a ^ b));
            c = Bits.RotateLeft32(c, 15);
            b = b + (data[3] + (c ^ d ^ a));
            b = Bits.RotateLeft32(b, 12);
            a = a + (data[4] + (b ^ c ^ d));
            a = Bits.RotateLeft32(a, 5);
            d = d + (data[5] + (a ^ b ^ c));
            d = Bits.RotateLeft32(d, 8);
            c = c + (data[6] + (d ^ a ^ b));
            c = Bits.RotateLeft32(c, 7);
            b = b + (data[7] + (c ^ d ^ a));
            b = Bits.RotateLeft32(b, 9);
            a = a + (data[8] + (b ^ c ^ d));
            a = Bits.RotateLeft32(a, 11);
            d = d + (data[9] + (a ^ b ^ c));
            d = Bits.RotateLeft32(d, 13);
            c = c + (data[10] + (d ^ a ^ b));
            c = Bits.RotateLeft32(c, 14);
            b = b + (data[11] + (c ^ d ^ a));
            b = Bits.RotateLeft32(b, 15);
            a = a + (data[12] + (b ^ c ^ d));
            a = Bits.RotateLeft32(a, 6);
            d = d + (data[13] + (a ^ b ^ c));
            d = Bits.RotateLeft32(d, 7);
            c = c + (data[14] + (d ^ a ^ b));
            c = Bits.RotateLeft32(c, 9);
            b = b + (data[15] + (c ^ d ^ a));
            b = Bits.RotateLeft32(b, 8);

            aa = aa + (data[5] + C1 + ((bb & dd) | (cc & ~dd)));
            aa = Bits.RotateLeft32(aa, 8);
            dd = dd + (data[14] + C1 + ((aa & cc) | (bb & ~cc)));
            dd = Bits.RotateLeft32(dd, 9);
            cc = cc + (data[7] + C1 + ((dd & bb) | (aa & ~bb)));
            cc = Bits.RotateLeft32(cc, 9);
            bb = bb + (data[0] + C1 + ((cc & aa) | (dd & ~aa)));
            bb = Bits.RotateLeft32(bb, 11);
            aa = aa + (data[9] + C1 + ((bb & dd) | (cc & ~dd)));
            aa = Bits.RotateLeft32(aa, 13);
            dd = dd + (data[2] + C1 + ((aa & cc) | (bb & ~cc)));
            dd = Bits.RotateLeft32(dd, 15);
            cc = cc + (data[11] + C1 + ((dd & bb) | (aa & ~bb)));
            cc = Bits.RotateLeft32(cc, 15);
            bb = bb + (data[4] + C1 + ((cc & aa) | (dd & ~aa)));
            bb = Bits.RotateLeft32(bb, 5);
            aa = aa + (data[13] + C1 + ((bb & dd) | (cc & ~dd)));
            aa = Bits.RotateLeft32(aa, 7);
            dd = dd + (data[6] + C1 + ((aa & cc) | (bb & ~cc)));
            dd = Bits.RotateLeft32(dd, 7);
            cc = cc + (data[15] + C1 + ((dd & bb) | (aa & ~bb)));
            cc = Bits.RotateLeft32(cc, 8);
            bb = bb + (data[8] + C1 + ((cc & aa) | (dd & ~aa)));
            bb = Bits.RotateLeft32(bb, 11);
            aa = aa + (data[1] + C1 + ((bb & dd) | (cc & ~dd)));
            aa = Bits.RotateLeft32(aa, 14);
            dd = dd + (data[10] + C1 + ((aa & cc) | (bb & ~cc)));
            dd = Bits.RotateLeft32(dd, 14);
            cc = cc + (data[3] + C1 + ((dd & bb) | (aa & ~bb)));
            cc = Bits.RotateLeft32(cc, 12);
            bb = bb + (data[12] + C1 + ((cc & aa) | (dd & ~aa)));
            bb = Bits.RotateLeft32(bb, 6);

            aa = aa + (data[7] + C2 + ((b & c) | (~b & d)));
            aa = Bits.RotateLeft32(aa, 7);
            d = d + (data[4] + C2 + ((aa & b) | (~aa & c)));
            d = Bits.RotateLeft32(d, 6);
            c = c + (data[13] + C2 + ((d & aa) | (~d & b)));
            c = Bits.RotateLeft32(c, 8);
            b = b + (data[1] + C2 + ((c & d) | (~c & aa)));
            b = Bits.RotateLeft32(b, 13);
            aa = aa + (data[10] + C2 + ((b & c) | (~b & d)));
            aa = Bits.RotateLeft32(aa, 11);
            d = d + (data[6] + C2 + ((aa & b) | (~aa & c)));
            d = Bits.RotateLeft32(d, 9);
            c = c + (data[15] + C2 + ((d & aa) | (~d & b)));
            c = Bits.RotateLeft32(c, 7);
            b = b + (data[3] + C2 + ((c & d) | (~c & aa)));
            b = Bits.RotateLeft32(b, 15);
            aa = aa + (data[12] + C2 + ((b & c) | (~b & d)));
            aa = Bits.RotateLeft32(aa, 7);
            d = d + (data[0] + C2 + ((aa & b) | (~aa & c)));
            d = Bits.RotateLeft32(d, 12);
            c = c + (data[9] + C2 + ((d & aa) | (~d & b)));
            c = Bits.RotateLeft32(c, 15);
            b = b + (data[5] + C2 + ((c & d) | (~c & aa)));
            b = Bits.RotateLeft32(b, 9);
            aa = aa + (data[2] + C2 + ((b & c) | (~b & d)));
            aa = Bits.RotateLeft32(aa, 11);
            d = d + (data[14] + C2 + ((aa & b) | (~aa & c)));
            d = Bits.RotateLeft32(d, 7);
            c = c + (data[11] + C2 + ((d & aa) | (~d & b)));
            c = Bits.RotateLeft32(c, 13);
            b = b + (data[8] + C2 + ((c & d) | (~c & aa)));
            b = Bits.RotateLeft32(b, 12);

            a = a + (data[6] + C3 + ((bb | ~cc) ^ dd));
            a = Bits.RotateLeft32(a, 9);
            dd = dd + (data[11] + C3 + ((a | ~bb) ^ cc));
            dd = Bits.RotateLeft32(dd, 13);
            cc = cc + (data[3] + C3 + ((dd | ~a) ^ bb));
            cc = Bits.RotateLeft32(cc, 15);
            bb = bb + (data[7] + C3 + ((cc | ~dd) ^ a));
            bb = Bits.RotateLeft32(bb, 7);
            a = a + (data[0] + C3 + ((bb | ~cc) ^ dd));
            a = Bits.RotateLeft32(a, 12);
            dd = dd + (data[13] + C3 + ((a | ~bb) ^ cc));
            dd = Bits.RotateLeft32(dd, 8);
            cc = cc + (data[5] + C3 + ((dd | ~a) ^ bb));
            cc = Bits.RotateLeft32(cc, 9);
            bb = bb + (data[10] + C3 + ((cc | ~dd) ^ a));
            bb = Bits.RotateLeft32(bb, 11);
            a = a + (data[14] + C3 + ((bb | ~cc) ^ dd));
            a = Bits.RotateLeft32(a, 7);
            dd = dd + (data[15] + C3 + ((a | ~bb) ^ cc));
            dd = Bits.RotateLeft32(dd, 7);
            cc = cc + (data[8] + C3 + ((dd | ~a) ^ bb));
            cc = Bits.RotateLeft32(cc, 12);
            bb = bb + (data[12] + C3 + ((cc | ~dd) ^ a));
            bb = Bits.RotateLeft32(bb, 7);
            a = a + (data[4] + C3 + ((bb | ~cc) ^ dd));
            a = Bits.RotateLeft32(a, 6);
            dd = dd + (data[9] + C3 + ((a | ~bb) ^ cc));
            dd = Bits.RotateLeft32(dd, 15);
            cc = cc + (data[1] + C3 + ((dd | ~a) ^ bb));
            cc = Bits.RotateLeft32(cc, 13);
            bb = bb + (data[2] + C3 + ((cc | ~dd) ^ a));
            bb = Bits.RotateLeft32(bb, 11);

            aa = aa + (data[3] + C4 + ((bb | ~c) ^ d));
            aa = Bits.RotateLeft32(aa, 11);
            d = d + (data[10] + C4 + ((aa | ~bb) ^ c));
            d = Bits.RotateLeft32(d, 13);
            c = c + (data[14] + C4 + ((d | ~aa) ^ bb));
            c = Bits.RotateLeft32(c, 6);
            bb = bb + (data[4] + C4 + ((c | ~d) ^ aa));
            bb = Bits.RotateLeft32(bb, 7);
            aa = aa + (data[9] + C4 + ((bb | ~c) ^ d));
            aa = Bits.RotateLeft32(aa, 14);
            d = d + (data[15] + C4 + ((aa | ~bb) ^ c));
            d = Bits.RotateLeft32(d, 9);
            c = c + (data[8] + C4 + ((d | ~aa) ^ bb));
            c = Bits.RotateLeft32(c, 13);
            bb = bb + (data[1] + C4 + ((c | ~d) ^ aa));
            bb = Bits.RotateLeft32(bb, 15);
            aa = aa + (data[2] + C4 + ((bb | ~c) ^ d));
            aa = Bits.RotateLeft32(aa, 14);
            d = d + (data[7] + C4 + ((aa | ~bb) ^ c));
            d = Bits.RotateLeft32(d, 8);
            c = c + (data[0] + C4 + ((d | ~aa) ^ bb));
            c = Bits.RotateLeft32(c, 13);
            bb = bb + (data[6] + C4 + ((c | ~d) ^ aa));
            bb = Bits.RotateLeft32(bb, 6);
            aa = aa + (data[13] + C4 + ((bb | ~c) ^ d));
            aa = Bits.RotateLeft32(aa, 5);
            d = d + (data[11] + C4 + ((aa | ~bb) ^ c));
            d = Bits.RotateLeft32(d, 12);
            c = c + (data[5] + C4 + ((d | ~aa) ^ bb));
            c = Bits.RotateLeft32(c, 7);
            bb = bb + (data[12] + C4 + ((c | ~d) ^ aa));
            bb = Bits.RotateLeft32(bb, 5);

            a = a + (data[15] + C5 + ((b & cc) | (~b & dd)));
            a = Bits.RotateLeft32(a, 9);
            dd = dd + (data[5] + C5 + ((a & b) | (~a & cc)));
            dd = Bits.RotateLeft32(dd, 7);
            cc = cc + (data[1] + C5 + ((dd & a) | (~dd & b)));
            cc = Bits.RotateLeft32(cc, 15);
            b = b + (data[3] + C5 + ((cc & dd) | (~cc & a)));
            b = Bits.RotateLeft32(b, 11);
            a = a + (data[7] + C5 + ((b & cc) | (~b & dd)));
            a = Bits.RotateLeft32(a, 8);
            dd = dd + (data[14] + C5 + ((a & b) | (~a & cc)));
            dd = Bits.RotateLeft32(dd, 6);
            cc = cc + (data[6] + C5 + ((dd & a) | (~dd & b)));
            cc = Bits.RotateLeft32(cc, 6);
            b = b + (data[9] + C5 + ((cc & dd) | (~cc & a)));
            b = Bits.RotateLeft32(b, 14);
            a = a + (data[11] + C5 + ((b & cc) | (~b & dd)));
            a = Bits.RotateLeft32(a, 12);
            dd = dd + (data[8] + C5 + ((a & b) | (~a & cc)));
            dd = Bits.RotateLeft32(dd, 13);
            cc = cc + (data[12] + C5 + ((dd & a) | (~dd & b)));
            cc = Bits.RotateLeft32(cc, 5);
            b = b + (data[2] + C5 + ((cc & dd) | (~cc & a)));
            b = Bits.RotateLeft32(b, 14);
            a = a + (data[10] + C5 + ((b & cc) | (~b & dd)));
            a = Bits.RotateLeft32(a, 13);
            dd = dd + (data[0] + C5 + ((a & b) | (~a & cc)));
            dd = Bits.RotateLeft32(dd, 13);
            cc = cc + (data[4] + C5 + ((dd & a) | (~dd & b)));
            cc = Bits.RotateLeft32(cc, 7);
            b = b + (data[13] + C5 + ((cc & dd) | (~cc & a)));
            b = Bits.RotateLeft32(b, 5);

            aa = aa + (data[1] + C6 + ((bb & d) | (cc & ~d)));
            aa = Bits.RotateLeft32(aa, 11);
            d = d + (data[9] + C6 + ((aa & cc) | (bb & ~cc)));
            d = Bits.RotateLeft32(d, 12);
            cc = cc + (data[11] + C6 + ((d & bb) | (aa & ~bb)));
            cc = Bits.RotateLeft32(cc, 14);
            bb = bb + (data[10] + C6 + ((cc & aa) | (d & ~aa)));
            bb = Bits.RotateLeft32(bb, 15);
            aa = aa + (data[0] + C6 + ((bb & d) | (cc & ~d)));
            aa = Bits.RotateLeft32(aa, 14);
            d = d + (data[8] + C6 + ((aa & cc) | (bb & ~cc)));
            d = Bits.RotateLeft32(d, 15);
            cc = cc + (data[12] + C6 + ((d & bb) | (aa & ~bb)));
            cc = Bits.RotateLeft32(cc, 9);
            bb = bb + (data[4] + C6 + ((cc & aa) | (d & ~aa)));
            bb = Bits.RotateLeft32(bb, 8);
            aa = aa + (data[13] + C6 + ((bb & d) | (cc & ~d)));
            aa = Bits.RotateLeft32(aa, 9);
            d = d + (data[3] + C6 + ((aa & cc) | (bb & ~cc)));
            d = Bits.RotateLeft32(d, 14);
            cc = cc + (data[7] + C6 + ((d & bb) | (aa & ~bb)));
            cc = Bits.RotateLeft32(cc, 5);
            bb = bb + (data[15] + C6 + ((cc & aa) | (d & ~aa)));
            bb = Bits.RotateLeft32(bb, 6);
            aa = aa + (data[14] + C6 + ((bb & d) | (cc & ~d)));
            aa = Bits.RotateLeft32(aa, 8);
            d = d + (data[5] + C6 + ((aa & cc) | (bb & ~cc)));
            d = Bits.RotateLeft32(d, 6);
            cc = cc + (data[6] + C6 + ((d & bb) | (aa & ~bb)));
            cc = Bits.RotateLeft32(cc, 5);
            bb = bb + (data[2] + C6 + ((cc & aa) | (d & ~aa)));
            bb = Bits.RotateLeft32(bb, 12);

            a = a + (data[8] + (b ^ c ^ dd));
            a = Bits.RotateLeft32(a, 15);
            dd = dd + (data[6] + (a ^ b ^ c));
            dd = Bits.RotateLeft32(dd, 5);
            c = c + (data[4] + (dd ^ a ^ b));
            c = Bits.RotateLeft32(c, 8);
            b = b + (data[1] + (c ^ dd ^ a));
            b = Bits.RotateLeft32(b, 11);
            a = a + (data[3] + (b ^ c ^ dd));
            a = Bits.RotateLeft32(a, 14);
            dd = dd + (data[11] + (a ^ b ^ c));
            dd = Bits.RotateLeft32(dd, 14);
            c = c + (data[15] + (dd ^ a ^ b));
            c = Bits.RotateLeft32(c, 6);
            b = b + (data[0] + (c ^ dd ^ a));
            b = Bits.RotateLeft32(b, 14);
            a = a + (data[5] + (b ^ c ^ dd));
            a = Bits.RotateLeft32(a, 6);
            dd = dd + (data[12] + (a ^ b ^ c));
            dd = Bits.RotateLeft32(dd, 9);
            c = c + (data[2] + (dd ^ a ^ b));
            c = Bits.RotateLeft32(c, 12);
            b = b + (data[13] + (c ^ dd ^ a));
            b = Bits.RotateLeft32(b, 9);
            a = a + (data[9] + (b ^ c ^ dd));
            a = Bits.RotateLeft32(a, 12);
            dd = dd + (data[7] + (a ^ b ^ c));
            dd = Bits.RotateLeft32(dd, 5);
            c = c + (data[10] + (dd ^ a ^ b));
            c = Bits.RotateLeft32(c, 15);
            b = b + (data[14] + (c ^ dd ^ a));
            b = Bits.RotateLeft32(b, 8);

            state[0] = state[0] + aa;
            state[1] = state[1] + bb;
            state[2] = state[2] + cc;
            state[3] = state[3] + dd;
            state[4] = state[4] + a;
            state[5] = state[5] + b;
            state[6] = state[6] + c;
            state[7] = state[7] + d;

            Utils.Utils.Memset(ref data, 0);
        } // end function TransformBlock
    } // end class RIPEMD256
}