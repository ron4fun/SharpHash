using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    internal sealed class SHA2_512 : SHA2_512Base
    {
        public SHA2_512() :
            base(64)
        { } // end constructor

        override public IHash Clone()
        {
            SHA2_512 HashInstance = new SHA2_512();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.state = new UInt64[state.Length];
            Utils.Utils.memcopy(ref HashInstance.state, state, state.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override public unsafe void Initialize()
        {
            state[0] = 0x6A09E667F3BCC908;
            state[1] = 0xBB67AE8584CAA73B;
            state[2] = 0x3C6EF372FE94F82B;
            state[3] = 0xA54FF53A5F1D36F1;
            state[4] = 0x510E527FADE682D1;
            state[5] = 0x9B05688C2B3E6C1F;
            state[6] = 0x1F83D9ABFB41BD6B;
            state[7] = 0x5BE0CD19137E2179;

            base.Initialize();
        } // end function Initialize

        override protected unsafe byte[] GetResult()
        {
            byte[] result = new byte[8 * sizeof(UInt64)];

            fixed (UInt64* sPtr = state)
            {
                fixed (byte* bPtr = result)
                {
                    Converters.be64_copy((IntPtr)sPtr, 0, (IntPtr)bPtr, 0, result.Length);
                }
            }

            return result;
        } // end function GetResult

    } // end class SHA2_512

}
