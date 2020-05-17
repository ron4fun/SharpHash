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
    internal sealed class Panama : BlockHash, ICryptoNotBuildIn, ITransformBlock
    {
        private UInt32[][] stages = null;
        private UInt32[] state, theta, gamma, pi, work_buffer;

        private Int32 tap;

        public Panama()
            : base(32, 32)
        {
            tap = 0;
            state = new UInt32[17];
            theta = new UInt32[17];
            gamma = new UInt32[17];
            pi = new UInt32[17];
            work_buffer = new UInt32[17];

            Array.Resize(ref stages, 32);
            for (Int32 i = 0; i < 32; i++)
                stages[i] = new UInt32[8];
        } // end constructor

        public override IHash Clone()
        {
            Panama HashInstance = new Panama();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.tap = tap;

            HashInstance.state = state.DeepCopy();
            HashInstance.theta = theta.DeepCopy();
            HashInstance.gamma = gamma.DeepCopy();
            HashInstance.pi = pi.DeepCopy();

            Array.Resize(ref stages, 32);
            for (UInt32 i = 0; i < 32; i++)
                Utils.Utils.Memcopy(ref HashInstance.stages[i], stages[i], stages[i].Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override unsafe void Initialize()
        {
            ArrayUtils.ZeroFill(ref state);

            for (Int32 i = 0; i < 32; i++)
                ArrayUtils.ZeroFill(ref stages[i]);

            base.Initialize();
        } // end function Initialize

        protected override unsafe byte[] GetResult()
        {
            byte[] result = new byte[8 * sizeof(UInt32)];

            fixed (UInt32* statePtr = &state[9])
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.le32_copy((IntPtr)statePtr, 0, (IntPtr)resultPtr, 0,
                        result.Length);
                }
            }

            return result;
        } // end function GetResult

        protected override unsafe void Finish()
        {
            Int32 tap4, tap16, tap25;

            Int32 padding_size = 32 - (Int32)(processed_bytes & 31);

            byte[] pad = new byte[padding_size];

            pad[0] = 0x01;
            TransformBytes(pad, 0, padding_size);

            UInt32[] theta = new UInt32[17];

            fixed (UInt32* ptr_theta = theta)
            {
                for (Int32 i = 0; i < 32; i++)
                {
                    tap4 = (tap + 4) & 0x1F;
                    tap16 = (tap + 16) & 0x1F;

                    tap = (tap - 1) & 0x1F;
                    tap25 = (tap + 25) & 0x1F;

                    GPT(ptr_theta);

                    stages[tap25][0] = stages[tap25][0] ^ stages[tap][2];
                    stages[tap25][1] = stages[tap25][1] ^ stages[tap][3];
                    stages[tap25][2] = stages[tap25][2] ^ stages[tap][4];
                    stages[tap25][3] = stages[tap25][3] ^ stages[tap][5];
                    stages[tap25][4] = stages[tap25][4] ^ stages[tap][6];
                    stages[tap25][5] = stages[tap25][5] ^ stages[tap][7];
                    stages[tap25][6] = stages[tap25][6] ^ stages[tap][0];
                    stages[tap25][7] = stages[tap25][7] ^ stages[tap][1];
                    stages[tap][0] = stages[tap][0] ^ state[1];
                    stages[tap][1] = stages[tap][1] ^ state[2];
                    stages[tap][2] = stages[tap][2] ^ state[3];
                    stages[tap][3] = stages[tap][3] ^ state[4];
                    stages[tap][4] = stages[tap][4] ^ state[5];
                    stages[tap][5] = stages[tap][5] ^ state[6];
                    stages[tap][6] = stages[tap][6] ^ state[7];
                    stages[tap][7] = stages[tap][7] ^ state[8];

                    state[0] = theta[0] ^ 0x01;
                    state[1] = theta[1] ^ stages[tap4][0];
                    state[2] = theta[2] ^ stages[tap4][1];
                    state[3] = theta[3] ^ stages[tap4][2];
                    state[4] = theta[4] ^ stages[tap4][3];
                    state[5] = theta[5] ^ stages[tap4][4];
                    state[6] = theta[6] ^ stages[tap4][5];
                    state[7] = theta[7] ^ stages[tap4][6];
                    state[8] = theta[8] ^ stages[tap4][7];
                    state[9] = theta[9] ^ stages[tap16][0];
                    state[10] = theta[10] ^ stages[tap16][1];
                    state[11] = theta[11] ^ stages[tap16][2];
                    state[12] = theta[12] ^ stages[tap16][3];
                    state[13] = theta[13] ^ stages[tap16][4];
                    state[14] = theta[14] ^ stages[tap16][5];
                    state[15] = theta[15] ^ stages[tap16][6];
                    state[16] = theta[16] ^ stages[tap16][7];
                } // end for
            }
        } // end function Finish

        protected override unsafe void TransformBlock(IntPtr a_data,
                Int32 a_data_length, Int32 a_index)
        {
            UInt32 tap16, tap25;

            fixed (UInt32* thetaPtr = theta, workPtr = work_buffer)
            {
                Converters.le32_copy(a_data, a_index, (IntPtr)workPtr, 0, 32);

                tap16 = (UInt32)((tap + 16) & 0x1F);

                tap = (tap - 1) & 0x1F;
                tap25 = (UInt32)((tap + 25) & 0x1F);

                GPT(thetaPtr);

                stages[tap25][0] = stages[tap25][0] ^ stages[tap][2];
                stages[tap25][1] = stages[tap25][1] ^ stages[tap][3];
                stages[tap25][2] = stages[tap25][2] ^ stages[tap][4];
                stages[tap25][3] = stages[tap25][3] ^ stages[tap][5];
                stages[tap25][4] = stages[tap25][4] ^ stages[tap][6];
                stages[tap25][5] = stages[tap25][5] ^ stages[tap][7];
                stages[tap25][6] = stages[tap25][6] ^ stages[tap][0];
                stages[tap25][7] = stages[tap25][7] ^ stages[tap][1];
                stages[tap][0] = stages[tap][0] ^ work_buffer[0];
                stages[tap][1] = stages[tap][1] ^ work_buffer[1];
                stages[tap][2] = stages[tap][2] ^ work_buffer[2];
                stages[tap][3] = stages[tap][3] ^ work_buffer[3];
                stages[tap][4] = stages[tap][4] ^ work_buffer[4];
                stages[tap][5] = stages[tap][5] ^ work_buffer[5];
                stages[tap][6] = stages[tap][6] ^ work_buffer[6];
                stages[tap][7] = stages[tap][7] ^ work_buffer[7];

                state[0] = theta[0] ^ 0x01;
                state[1] = theta[1] ^ work_buffer[0];
                state[2] = theta[2] ^ work_buffer[1];
                state[3] = theta[3] ^ work_buffer[2];
                state[4] = theta[4] ^ work_buffer[3];
                state[5] = theta[5] ^ work_buffer[4];
                state[6] = theta[6] ^ work_buffer[5];
                state[7] = theta[7] ^ work_buffer[6];
                state[8] = theta[8] ^ work_buffer[7];
                state[9] = theta[9] ^ stages[tap16][0];
                state[10] = theta[10] ^ stages[tap16][1];
                state[11] = theta[11] ^ stages[tap16][2];
                state[12] = theta[12] ^ stages[tap16][3];
                state[13] = theta[13] ^ stages[tap16][4];
                state[14] = theta[14] ^ stages[tap16][5];
                state[15] = theta[15] ^ stages[tap16][6];
                state[16] = theta[16] ^ stages[tap16][7];

                Utils.Utils.Memset(ref work_buffer, 0);
            }
        } // end function TransformBlock

        private unsafe void GPT(UInt32* a_theta)
        {
            gamma[0] = state[0] ^ (state[1] | ~state[2]);
            gamma[1] = state[1] ^ (state[2] | ~state[3]);
            gamma[2] = state[2] ^ (state[3] | ~state[4]);
            gamma[3] = state[3] ^ (state[4] | ~state[5]);
            gamma[4] = state[4] ^ (state[5] | ~state[6]);
            gamma[5] = state[5] ^ (state[6] | ~state[7]);
            gamma[6] = state[6] ^ (state[7] | ~state[8]);
            gamma[7] = state[7] ^ (state[8] | ~state[9]);
            gamma[8] = state[8] ^ (state[9] | ~state[10]);
            gamma[9] = state[9] ^ (state[10] | ~state[11]);
            gamma[10] = state[10] ^ (state[11] | ~state[12]);
            gamma[11] = state[11] ^ (state[12] | ~state[13]);
            gamma[12] = state[12] ^ (state[13] | ~state[14]);
            gamma[13] = state[13] ^ (state[14] | ~state[15]);
            gamma[14] = state[14] ^ (state[15] | ~state[16]);
            gamma[15] = state[15] ^ (state[16] | ~state[0]);
            gamma[16] = state[16] ^ (state[0] | ~state[1]);

            pi[0] = gamma[0];
            pi[1] = Bits.RotateLeft32(gamma[7], 1);
            pi[2] = Bits.RotateLeft32(gamma[14], 3);
            pi[3] = Bits.RotateLeft32(gamma[4], 6);
            pi[4] = Bits.RotateLeft32(gamma[11], 10);
            pi[5] = Bits.RotateLeft32(gamma[1], 15);
            pi[6] = Bits.RotateLeft32(gamma[8], 21);
            pi[7] = Bits.RotateLeft32(gamma[15], 28);
            pi[8] = Bits.RotateLeft32(gamma[5], 4);
            pi[9] = Bits.RotateLeft32(gamma[12], 13);
            pi[10] = Bits.RotateLeft32(gamma[2], 23);
            pi[11] = Bits.RotateLeft32(gamma[9], 2);
            pi[12] = Bits.RotateLeft32(gamma[16], 14);
            pi[13] = Bits.RotateLeft32(gamma[6], 27);
            pi[14] = Bits.RotateLeft32(gamma[13], 9);
            pi[15] = Bits.RotateLeft32(gamma[3], 24);
            pi[16] = Bits.RotateLeft32(gamma[10], 8);

            a_theta[0] = pi[0] ^ pi[1] ^ pi[4];
            a_theta[1] = pi[1] ^ pi[2] ^ pi[5];
            a_theta[2] = pi[2] ^ pi[3] ^ pi[6];
            a_theta[3] = pi[3] ^ pi[4] ^ pi[7];
            a_theta[4] = pi[4] ^ pi[5] ^ pi[8];
            a_theta[5] = pi[5] ^ pi[6] ^ pi[9];
            a_theta[6] = pi[6] ^ pi[7] ^ pi[10];
            a_theta[7] = pi[7] ^ pi[8] ^ pi[11];
            a_theta[8] = pi[8] ^ pi[9] ^ pi[12];
            a_theta[9] = pi[9] ^ pi[10] ^ pi[13];
            a_theta[10] = pi[10] ^ pi[11] ^ pi[14];
            a_theta[11] = pi[11] ^ pi[12] ^ pi[15];
            a_theta[12] = pi[12] ^ pi[13] ^ pi[16];
            a_theta[13] = pi[13] ^ pi[14] ^ pi[0];
            a_theta[14] = pi[14] ^ pi[15] ^ pi[1];
            a_theta[15] = pi[15] ^ pi[16] ^ pi[2];
            a_theta[16] = pi[16] ^ pi[0] ^ pi[3];
        } // end function GPT

    } // end class Panama
}