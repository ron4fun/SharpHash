using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    internal sealed class SHA2_224 : SHA2_256Base
    {
        public SHA2_224() :
            base(28)
        { } // end constructor

        public override IHash Clone()
        {
            SHA2_224 HashInstance = new SHA2_224();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.state = new UInt32[state.Length];
            Utils.Utils.memcopy(ref HashInstance.state, state, state.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override unsafe void Initialize()
        {
            state[0] = 0xC1059ED8;
            state[1] = 0x367CD507;
            state[2] = 0x3070DD17;
            state[3] = 0xF70E5939;
            state[4] = 0xFFC00B31;
            state[5] = 0x68581511;
            state[6] = 0x64F98FA7;
            state[7] = 0xBEFA4FA4;

            base.Initialize();
        } // end function Initialize

        protected override unsafe byte[] GetResult()
        {
            byte[] result = new byte[7 * sizeof(UInt32)];

            fixed (UInt32* sPtr = state)
            {
                fixed (byte* bPtr = result)
                {
                    Converters.be32_copy((IntPtr)sPtr, 0, (IntPtr)bPtr, 0, result.Length);
                }
            }

            return result;
        } // end function GetResult
    } // end class SHA2_224
}