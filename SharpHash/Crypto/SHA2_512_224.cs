using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    internal sealed class SHA2_512_224 : SHA2_512Base
    {
        public SHA2_512_224() :
            base(28)
        { } // end constructor

        public override IHash Clone()
        {
            SHA2_512_224 HashInstance = new SHA2_512_224();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.state = new UInt64[state.Length];
            Utils.Utils.memcopy(ref HashInstance.state, state, state.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override unsafe void Initialize()
        {
            state[0] = 0x8C3D37C819544DA2;
            state[1] = 0x73E1996689DCD4D6;
            state[2] = 0x1DFAB7AE32FF9C82;
            state[3] = 0x679DD514582F9FCF;
            state[4] = 0x0F6D2B697BD44DA8;
            state[5] = 0x77E36F7304C48942;
            state[6] = 0x3F9D85A86A1D36C8;
            state[7] = 0x1112E6AD91D692A1;

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

            Array.Resize(ref result, HashSize * sizeof(byte));

            return result;
        } // end function GetResult
    } // end class SHA2_512_224
}