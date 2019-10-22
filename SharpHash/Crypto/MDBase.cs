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
    internal abstract class MDBase : BlockHash, ICryptoNotBuildIn
    {
        protected readonly static UInt32 C1 = 0x50A28BE6;
        protected readonly static UInt32 C2 = 0x5A827999;
        protected readonly static UInt32 C3 = 0x5C4DD124;
        protected readonly static UInt32 C4 = 0x6ED9EBA1;
        protected readonly static UInt32 C5 = 0x6D703EF3;
        protected readonly static UInt32 C6 = 0x8F1BBCDC;
        protected readonly static UInt32 C7 = 0x7A6D76E9;
        protected readonly static UInt32 C8 = 0xA953FD4E;

        protected UInt32[] state = null;

        public MDBase(Int32 a_state_length, Int32 a_hash_size)
            : base(a_hash_size, 64)
        {
            state = new UInt32[a_state_length];
        } // end constructor

        protected override unsafe byte[] GetResult()
        {
            byte[] result = new byte[state.Length * sizeof(UInt32)];

            fixed (UInt32* statePtr = state)
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.le32_copy((IntPtr)statePtr, 0, (IntPtr)resultPtr, 0,
                        result.Length);
                }
            }

            return result;
        } // end function GetResult

        public override void Initialize()
        {
            state[0] = 0x67452301;
            state[1] = 0xEFCDAB89;
            state[2] = 0x98BADCFE;
            state[3] = 0x10325476;

            base.Initialize();
        } // end function Initialize

        protected override void Finish()
        {
            UInt64 bits;
            Int32 padindex;

            bits = processed_bytes * 8;
            if (buffer.Position < 56)
                padindex = 56 - buffer.Position;
            else
                padindex = 120 - buffer.Position;

            byte[] pad = new byte[padindex + 8];

            pad[0] = 0x80;

            bits = Converters.le2me_64(bits);

            Converters.ReadUInt64AsBytesLE(bits, ref pad, padindex);

            padindex = padindex + 8;

            TransformBytes(pad, 0, padindex);
        } // end function Finish
    } // end class MDBase
}