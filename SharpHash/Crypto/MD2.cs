using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    public class MD2 : BlockHash, ICryptoNotBuildIn, ITransformBlock
    {
        private byte[] state = null;
        private byte[] checksum = null;

        private readonly static byte[] pi = new byte[256] {41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
                19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
                30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18, 190, 78,
                196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122, 169, 104, 121,
                145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144,
                50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165, 181, 209, 215,
                94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107,
                226, 156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45,
                168, 2, 27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71,
                163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38, 44, 83, 13, 110, 133,
                40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250,
                36, 225, 123, 8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213,
                254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117,
                75, 10, 49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20};


        public MD2()
            : base(16, 16)
        {
            state = new byte[16];
            checksum = new byte[16];
        } // end constructor

        override public IHash Clone()
        {
            MD2 HashInstance = new MD2();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.state = new byte[state.Length];
            for (Int32 i = 0; i < state.Length; i++)
                HashInstance.state[i] = state[i];

            HashInstance.checksum = new byte[checksum.Length];
            for (Int32 i = 0; i < checksum.Length; i++)
                HashInstance.checksum[i] = checksum[i];

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override public unsafe void Initialize()
        {
            Utils.Utils.memset(state, 0);
            Utils.Utils.memset(checksum, 0);

            base.Initialize();
        } // end function Initialize

        override protected byte[] GetResult()
        {
            return state;
        } // end function GetResult

        override protected void Finish()
        {
            UInt32 padLen;

            padLen = 16 - (UInt32)buffer.Position;
            byte[] pad = new byte[padLen];

            UInt32 i = 0;
            while (i < padLen)
            {
                pad[i] = (byte)padLen;
                i++;
            } // end while

            TransformBytes(pad, 0, (Int32)padLen);
            TransformBytes(checksum, 0, 16);
        } // end function Finish

        override protected unsafe void TransformBlock(IntPtr a_data,
                Int32 a_data_length, Int32 a_index)
        {
            UInt32 t = 0;
            byte[] temp = new byte[48];

            fixed (byte* tempPtr = temp, statetPtr = state)
            {
                Utils.Utils.memmove((IntPtr)tempPtr, (IntPtr)statetPtr, a_data_length);
                Utils.Utils.memmove((IntPtr)((byte*)tempPtr + a_data_length), (IntPtr)((byte*)a_data + a_index), a_data_length);

                for (Int32 i = 0; i < 16; i++)
		        {
                    temp[i + 32] = (byte)(state[i] ^ ((byte*)a_data)[i + a_index]);
                } // end for

                for (Int32 i = 0; i < 18; i++)
		        {
                    for (Int32 j = 0; j < 48; j++)
			        {
                        temp[j] = (byte)(temp[j] ^ pi[t]);
                        t = temp[j];
                    } // end for

                    t = (byte)(t + i);
                } // end for

                Utils.Utils.memmove((IntPtr)statetPtr, (IntPtr)tempPtr, 16);

                t = checksum[15];

                for (Int32 i = 0; i < 16; i++)
		        {
                    checksum[i] = (byte)(checksum[i] ^ pi[((byte*)a_data)[i + a_index] ^ t]);
                    t = checksum[i];
                } // end for

                Utils.Utils.memset(temp, 0);
            }
            
        } // end function TransformBlock

    } // end class MD2

}
