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
using SharpHash.Crypto;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace SharpHash.KDF
{
    /// <summary>Implementation of the scrypt a password-based key derivation function.</summary>
    /// <remarks>
    /// Scrypt was created by Colin Percival and is specified in
    /// <a href="http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01">draft-josefsson-scrypt-kd</a>.
    /// </remarks>
    internal class PBKDF_ScryptNotBuildInAdapter : Base.KDF, IPBKDF_ScryptNotBuildIn
    {
        private byte[] PasswordBytes = null;
        private byte[] SaltBytes = null;
        private Int32 Cost, BlockSize, Parallelism;

        public static readonly string InvalidByteCount = "\"(ByteCount)\" Argument must be a value greater than zero.";
        public static readonly string InvalidCost = "Cost parameter must be > 1 and a power of 2.";
        public static readonly string BlockSizeAndCostIncompatible = "Cost parameter must be > 1 and < 65536.";
        public static readonly string BlockSizeTooSmall = "Block size must be >= 1.";
        public static readonly string InvalidParallelism = "Parallelism parameter must be >= 1 and <= {0} (based on block size of {1})";
        public static readonly string RoundsMustBeEven = "Number of Rounds Must be Even";

        public PBKDF_ScryptNotBuildInAdapter(byte[] a_PasswordBytes, byte[] a_SaltBytes,
            Int32 a_Cost, Int32 a_BlockSize, Int32 a_Parallelism)
        {
            ValidatePBKDF_ScryptInputs(a_Cost, a_BlockSize, a_Parallelism);

            PasswordBytes = new byte[a_PasswordBytes?.Length ?? 0];

            if (!(a_PasswordBytes == null || a_PasswordBytes.Length == 0))
                Utils.Utils.memcopy(ref PasswordBytes, a_PasswordBytes, a_PasswordBytes.Length);

            SaltBytes = new byte[a_SaltBytes?.Length ?? 0];

            if (!(a_SaltBytes == null || a_SaltBytes.Length == 0))
                Utils.Utils.memcopy(ref SaltBytes, a_SaltBytes, a_SaltBytes.Length);

            Cost = a_Cost;
            BlockSize = a_BlockSize;
            Parallelism = a_Parallelism;
        } //

        ~PBKDF_ScryptNotBuildInAdapter()
        {
            Clear();
        } //

        public static void ValidatePBKDF_ScryptInputs(Int32 a_Cost, Int32 a_BlockSize,
            Int32 a_Parallelism)
        {
            Int32 LMaxParallel;

            if ((a_Cost <= 1) || (!IsPowerOf2(a_Cost)))
                throw new ArgumentHashLibException(InvalidCost);

            // Only value of ABlockSize that cost (as an int) could be exceeded for is 1
            if ((a_BlockSize == 1) && (a_Cost >= 65536))
                throw new ArgumentHashLibException(BlockSizeAndCostIncompatible);

            if (a_BlockSize < 1)
                throw new ArgumentHashLibException(BlockSizeTooSmall);

            LMaxParallel = Int32.MaxValue / (128 * a_BlockSize * 8);

            if ((a_Parallelism < 1) || (a_Parallelism > LMaxParallel))
                throw new ArgumentHashLibException(
                    String.Format(InvalidParallelism, LMaxParallel, a_BlockSize));
        } //

        public override void Clear()
        {
            Utils.Utils.memset(ref PasswordBytes, 0);
            Utils.Utils.memset(ref SaltBytes, 0);
        } // end function Clear

        /// <summary>
        /// Returns the pseudo-random bytes for this object.
        /// </summary>
        /// <param name="ByteCount">The number of pseudo-random key bytes to generate.</param>
        /// <returns>A byte array filled with pseudo-random key bytes.</returns>
        /// /// <exception cref="ArgumentOutOfRangeHashLibException">AByteCount must be greater than zero.</exception>
        public override byte[] GetBytes(Int32 ByteCount)
        {
            if (ByteCount <= 0)
                throw new ArgumentHashLibException(InvalidByteCount);

            return MFCrypt(PasswordBytes, SaltBytes, Cost, BlockSize, Parallelism, ByteCount);
        } // end function GetBytes

        private static void ClearArray(ref byte[] a_Input)
        {
            Utils.Utils.memset(ref a_Input, 0);
        } //

        private static void ClearArray(ref UInt32[] a_Input)
        {
            Utils.Utils.memset(ref a_Input, 0);
        } //

        private static void ClearAllArrays(ref UInt32[][] a_Inputs)
        {
            for (Int32 i = 0; i < a_Inputs.Length; i++)
            {
                ClearArray(ref a_Inputs[i]);
            } //
        } //

        private static bool IsPowerOf2(Int32 x)
        {
            return (x > 0) && ((x & (x - 1)) == 0);
        } //

        private static byte[] SingleIterationPBKDF2(byte[] a_PasswordBytes,
            byte[] a_SaltBytes, Int32 a_OutputLength)
        {
            return (new PBKDF2_HMACNotBuildInAdapter(new SHA2_256() as IHash, a_PasswordBytes,
                a_SaltBytes, 1) as IPBKDF2_HMAC).GetBytes(a_OutputLength);
        } //

        /// <summary>
        /// Rotate left
        /// </summary>
        /// <param name="a_Value">
        /// value to rotate
        /// </param>
        /// <param name="a_Distance">
        /// distance to rotate AValue
        /// </param>
        /// <returns>
        /// rotated AValue
        /// </returns>
        private static UInt32 Rotl(UInt32 a_Value, Int32 a_Distance)
        {
            return Bits.RotateLeft32(a_Value, a_Distance);
        } //

        /// <summary>
        /// lifted from <c>ClpSalsa20Engine.pas</c> in CryptoLib4Pascal with
        /// minor modifications.
        /// </summary>
        private static void SalsaCore(Int32 a_Rounds, UInt32[] a_Input, ref UInt32[] x)
        {
            UInt32 x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11, x12, x13, x14, x15;
            Int32 i;

            if (a_Input.Length != 16)
                throw new ArgumentHashLibException("");

            if (x.Length != 16)
                throw new ArgumentHashLibException("");

            if ((a_Rounds % 2) != 0)
                throw new ArgumentHashLibException(RoundsMustBeEven);

            x00 = a_Input[0];
            x01 = a_Input[1];
            x02 = a_Input[2];
            x03 = a_Input[3];
            x04 = a_Input[4];
            x05 = a_Input[5];
            x06 = a_Input[6];
            x07 = a_Input[7];
            x08 = a_Input[8];
            x09 = a_Input[9];
            x10 = a_Input[10];
            x11 = a_Input[11];
            x12 = a_Input[12];
            x13 = a_Input[13];
            x14 = a_Input[14];
            x15 = a_Input[15];

            i = a_Rounds;
            while (i > 0)
            {
                x04 = x04 ^ (Rotl((x00 + x12), 7));
                x08 = x08 ^ (Rotl((x04 + x00), 9));
                x12 = x12 ^ (Rotl((x08 + x04), 13));
                x00 = x00 ^ (Rotl((x12 + x08), 18));
                x09 = x09 ^ (Rotl((x05 + x01), 7));
                x13 = x13 ^ (Rotl((x09 + x05), 9));
                x01 = x01 ^ (Rotl((x13 + x09), 13));
                x05 = x05 ^ (Rotl((x01 + x13), 18));
                x14 = x14 ^ (Rotl((x10 + x06), 7));
                x02 = x02 ^ (Rotl((x14 + x10), 9));
                x06 = x06 ^ (Rotl((x02 + x14), 13));
                x10 = x10 ^ (Rotl((x06 + x02), 18));
                x03 = x03 ^ (Rotl((x15 + x11), 7));
                x07 = x07 ^ (Rotl((x03 + x15), 9));
                x11 = x11 ^ (Rotl((x07 + x03), 13));
                x15 = x15 ^ (Rotl((x11 + x07), 18));

                x01 = x01 ^ (Rotl((x00 + x03), 7));
                x02 = x02 ^ (Rotl((x01 + x00), 9));
                x03 = x03 ^ (Rotl((x02 + x01), 13));
                x00 = x00 ^ (Rotl((x03 + x02), 18));
                x06 = x06 ^ (Rotl((x05 + x04), 7));
                x07 = x07 ^ (Rotl((x06 + x05), 9));
                x04 = x04 ^ (Rotl((x07 + x06), 13));
                x05 = x05 ^ (Rotl((x04 + x07), 18));
                x11 = x11 ^ (Rotl((x10 + x09), 7));
                x08 = x08 ^ (Rotl((x11 + x10), 9));
                x09 = x09 ^ (Rotl((x08 + x11), 13));
                x10 = x10 ^ (Rotl((x09 + x08), 18));
                x12 = x12 ^ (Rotl((x15 + x14), 7));
                x13 = x13 ^ (Rotl((x12 + x15), 9));
                x14 = x14 ^ (Rotl((x13 + x12), 13));
                x15 = x15 ^ (Rotl((x14 + x13), 18));

                i -= 2;
            } //

            x[0] = x00 + a_Input[0];
            x[1] = x01 + a_Input[1];
            x[2] = x02 + a_Input[2];
            x[3] = x03 + a_Input[3];
            x[4] = x04 + a_Input[4];
            x[5] = x05 + a_Input[5];
            x[6] = x06 + a_Input[6];
            x[7] = x07 + a_Input[7];
            x[8] = x08 + a_Input[8];
            x[9] = x09 + a_Input[9];
            x[10] = x10 + a_Input[10];
            x[11] = x11 + a_Input[11];
            x[12] = x12 + a_Input[12];
            x[13] = x13 + a_Input[13];
            x[14] = x14 + a_Input[14];
            x[15] = x15 + a_Input[15];
        } //

        private static void Xor(UInt32[] a, UInt32[] b, Int32 bOff, ref UInt32[] a_Output)
        {
            Int32 i = a_Output.Length - 1;
            while (i >= 0)
            {
                a_Output[i] = a[i] ^ b[bOff + i];
                i--;
            } //
        } //

        private static void SMix(ref UInt32[] b, Int32 bOff, Int32 N, Int32 R)
        {
            Int32 LBCount, LIdx, LJdx, LOffset;
            UInt32 LMask;
            UInt32[] LBlockX1, LBlockX2, LBlockY, LX, LV;

            LBCount = R * 32;
            LBlockX1 = new UInt32[16];
            LBlockX2 = new UInt32[16];
            LBlockY = new UInt32[LBCount];

            LX = new UInt32[LBCount];

            LV = new UInt32[N * LBCount];

            try
            {
                Utils.Utils.memmove(ref LX, b, LBCount, bOff);

                LOffset = 0;
                LIdx = 0;
                while (LIdx < N)
                {
                    Utils.Utils.memmove(ref LV, LX, LBCount, 0, LOffset);
                    LOffset = LOffset + LBCount;
                    BlockMix(LX, ref LBlockX1, ref LBlockX2, ref LBlockY, R);
                    Utils.Utils.memmove(ref LV, LBlockY, LBCount, 0, LOffset);
                    LOffset = LOffset + LBCount;
                    BlockMix(LBlockY, ref LBlockX1, ref LBlockX2, ref LX, R);
                    LIdx += 2;
                } //

                LMask = (UInt32)N - 1;
                LIdx = 0;
                while (LIdx < N)
                {
                    LJdx = (Int32)(LX[LBCount - 16] & LMask);
                    Utils.Utils.memmove(ref LBlockY, LV, LBCount, LJdx * LBCount);
                    Xor(LBlockY, LX, 0, ref LBlockY);
                    BlockMix(LBlockY, ref LBlockX1, ref LBlockX2, ref LX, R);
                    LIdx++;
                } //

                Utils.Utils.memmove(ref b, LX, LBCount, 0, bOff);
            } //
            finally
            {
                UInt32[][] temp = new UInt32[][] { LX, LBlockX1, LBlockX2, LBlockY };
                ClearArray(ref LV);
                ClearAllArrays(ref temp);
            } //
        } //

        private static void BlockMix(UInt32[] b, ref UInt32[] X1, ref UInt32[] X2, ref UInt32[] y, Int32 R)
        {
            Int32 bOff, yOff, HalfLen, Idx;

            Utils.Utils.memmove(ref X1, b, 16, b.Length - 16);

            bOff = 0;
            yOff = 0;
            HalfLen = b.Length / 2;

            Idx = 2 * R;
            while (Idx > 0)
            {
                Xor(X1, b, bOff, ref X2);

                SalsaCore(8, X2, ref X1);

                Utils.Utils.memmove(ref y, X1, 16, 0, yOff);

                yOff = HalfLen + bOff - yOff;
                bOff = bOff + 16;

                Idx--;
            } //
        } //

        private static unsafe void DoSMix(ref UInt32[] b, Int32 a_Parallelism, Int32 a_Cost,
            Int32 a_BlockSize)
        {
            for (Int32 LIdx = 0; LIdx < a_Parallelism; LIdx++)
                SMix(ref b, LIdx * 32 * a_BlockSize, a_Cost, a_BlockSize);
        } //

        private static unsafe byte[] MFCrypt(byte[] a_PasswordBytes, byte[] a_SaltBytes, Int32 a_Cost,
            Int32 a_BlockSize, Int32 a_Parallelism, Int32 a_OutputLength)
        {
            Int32 LMFLenBytes, LBLen;
            byte[] LBytes, result;
            UInt32[] Lb = new UInt32[0];

            LMFLenBytes = a_BlockSize * 128;
            LBytes = SingleIterationPBKDF2(a_PasswordBytes, a_SaltBytes,
                a_Parallelism * LMFLenBytes);

            try
            {
                LBLen = LBytes.Length / 4;
                Lb = new UInt32[LBLen];

                fixed (UInt32* LbPtr = Lb)
                {
                    fixed (byte* bPtr = LBytes)
                    {
                        Converters.le32_copy((IntPtr)bPtr, 0, (IntPtr)LbPtr, 0,
                            LBytes.Length * sizeof(byte));

                        DoSMix(ref Lb, a_Parallelism, a_Cost, a_BlockSize);

                        Converters.le32_copy((IntPtr)LbPtr, 0, (IntPtr)bPtr, 0,
                            Lb.Length * sizeof(UInt32));
                    } //
                } //
                result = SingleIterationPBKDF2(a_PasswordBytes, LBytes, a_OutputLength);
            }
            finally
            {
                ClearArray(ref Lb);
                ClearArray(ref LBytes);
            } //

            return result;
        } //
    }
}