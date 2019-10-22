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
    internal sealed class SHA2_384 : SHA2_512Base
    {
        public SHA2_384() :
            base(48)
        { } // end constructor

        public override IHash Clone()
        {
            SHA2_384 HashInstance = new SHA2_384();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.state = new UInt64[state.Length];
            Utils.Utils.memcopy(ref HashInstance.state, state, state.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override unsafe void Initialize()
        {
            state[0] = 0xCBBB9D5DC1059ED8;
            state[1] = 0x629A292A367CD507;
            state[2] = 0x9159015A3070DD17;
            state[3] = 0x152FECD8F70E5939;
            state[4] = 0x67332667FFC00B31;
            state[5] = 0x8EB44A8768581511;
            state[6] = 0xDB0C2E0D64F98FA7;
            state[7] = 0x47B5481DBEFA4FA4;

            base.Initialize();
        } // end function Initialize

        protected override unsafe byte[] GetResult()
        {
            byte[] result = new byte[6 * sizeof(UInt64)];

            fixed (UInt64* sPtr = state)
            {
                fixed (byte* bPtr = result)
                {
                    Converters.be64_copy((IntPtr)sPtr, 0, (IntPtr)bPtr, 0, result.Length);
                }
            }

            return result;
        } // end function GetResult
    } // end class SHA2_384
}