using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    internal sealed class SHA2_512_256 : SHA2_512Base
    {
        public SHA2_512_256() :
            base(32)
        { } // end constructor

        public override IHash Clone()
        {
            SHA2_512_256 HashInstance = new SHA2_512_256();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.state = new UInt64[state.Length];
            Utils.Utils.memcopy(ref HashInstance.state, state, state.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override unsafe void Initialize()
        {
            state[0] = 0x22312194FC2BF72C;
            state[1] = 0x9F555FA3C84C64C2;
            state[2] = 0x2393B86B6F53B151;
            state[3] = 0x963877195940EABD;
            state[4] = 0x96283EE2A88EFFE3;
            state[5] = 0xBE5E1E2553863992;
            state[6] = 0x2B0199FC2C85B8AA;
            state[7] = 0x0EB72DDC81C52CA2;

            base.Initialize();
        } // end function Initialize

        protected override unsafe byte[] GetResult()
        {
            byte[] result = new byte[4 * sizeof(UInt64)];

            fixed (UInt64* sPtr = state)
            {
                fixed (byte* bPtr = result)
                {
                    Converters.be64_copy((IntPtr)sPtr, 0, (IntPtr)bPtr, 0, result.Length);
                }
            }

            return result;
        } // end function GetResult

    } // end class SHA2_512_256

}
