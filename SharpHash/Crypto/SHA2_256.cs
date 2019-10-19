using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    internal sealed class SHA2_256 : SHA2_256Base
    {
        public SHA2_256() :
            base(32)
        { } // end constructor

        override public IHash Clone()
        {
            SHA2_256 HashInstance = new SHA2_256();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.state = new UInt32[state.Length];
            Utils.Utils.memcopy(ref HashInstance.state, state, state.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override public unsafe void Initialize()
        {
            state[0] = 0x6A09E667;
            state[1] = 0xBB67AE85;
            state[2] = 0x3C6EF372;
            state[3] = 0xA54FF53A;
            state[4] = 0x510E527F;
            state[5] = 0x9B05688C;
            state[6] = 0x1F83D9AB;
            state[7] = 0x5BE0CD19;

            base.Initialize();
        } // end function Initialize

        override protected unsafe byte[] GetResult()
        {
            byte[] result = new byte[8 * sizeof(UInt32)];

            fixed (UInt32* sPtr = state)
            {
                fixed (byte* bPtr = result)
                {
                    Converters.be32_copy((IntPtr)sPtr, 0, (IntPtr)bPtr, 0, result.Length);
                }
            }

            return result;
        } // end function GetResult

    } // end class SHA2_256

}
