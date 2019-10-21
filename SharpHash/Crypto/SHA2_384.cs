using SharpHash.Base;
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
