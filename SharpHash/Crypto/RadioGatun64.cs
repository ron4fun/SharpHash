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
    internal sealed class RadioGatun64 : BlockHash, ICryptoNotBuildIn, ITransformBlock
    {
        private UInt64[] mill = null;
        private UInt64[][] belt = null;

        public RadioGatun64()
            : base(32, 24)
        {
            mill = new UInt64[19];

            Array.Resize(ref belt, 13);
            for (Int32 i = 0; i < 13; i++)
                belt[i] = new UInt64[3];
        } // end constructor

        public override IHash Clone()
        {
            RadioGatun64 HashInstance = new RadioGatun64();
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.mill = mill.DeepCopy();

            Array.Resize(ref belt, 13);
            for (Int32 i = 0; i < 13; i++)
                Utils.Utils.Memcopy(ref HashInstance.belt[i], belt[i], belt[i].Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override unsafe void Initialize()
        {
            ArrayUtils.ZeroFill(ref mill);

            for (Int32 i = 0; i < 13; i++)
                ArrayUtils.ZeroFill(ref belt[i]);

            base.Initialize();
        } // end function Initialize

        protected override unsafe byte[] GetResult()
        {
            UInt64[] tempRes = new UInt64[4];
            byte[] result = new byte[4 * sizeof(UInt64)];

            fixed (UInt64* tPtr = tempRes, millPtr = mill)
            {
                fixed (byte* resultPtr = result)
                {
                    for (Int32 i = 0; i < 2; i++)
                    {
                        RoundFunction();
                        Utils.Utils.Memmove((IntPtr)(tPtr + (i * 2)), (IntPtr)(millPtr + 1), 2 * sizeof(UInt64));
                    } // end for

                    Converters.le64_copy((IntPtr)tPtr, 0, (IntPtr)resultPtr, 0,
                        result.Length);
                }
            }

            return result;
        } // end function GetResult

        protected override unsafe void Finish()
        {
            Int32 padding_size = 24 - (Int32)(processed_bytes % 24);

            byte[] pad = new byte[padding_size];

            pad[0] = 0x01;

            TransformBytes(pad, 0, padding_size);

            for (Int32 i = 0; i < 16; i++)
                RoundFunction();
        } // end function Finish

        protected override unsafe void TransformBlock(IntPtr a_data,
                Int32 a_data_length, Int32 a_index)
        {
            UInt64[] data = new UInt64[3];

            fixed (UInt64* dataPtr = data)
            {
                Converters.le64_copy(a_data, a_index, (IntPtr)dataPtr, 0, 24);

                Int32 i = 0;
                while (i < 3)
                {
                    mill[i + 16] = mill[i + 16] ^ data[i];
                    belt[0][i] = belt[0][i] ^ data[i];
                    i++;
                } // end while

                RoundFunction();

                Utils.Utils.Memset(ref data, 0);
            }
        } // end function TransformBlock

        private unsafe void RoundFunction()
        {
            UInt64[] a = new UInt64[19];
            UInt64[] q = belt[12];

            Int32 i = 12;
            while (i > 0)
            {
                belt[i] = belt[i - 1];
                i--;
            } // end while

            belt[0] = q;

            i = 0;
            while (i < 12)
            {
                belt[i + 1][i % 3] = belt[i + 1][i % 3] ^ mill[i + 1];
                i++;
            } // end while

            i = 0;
            while (i < 19)
            {
                a[i] = mill[i] ^ (mill[(i + 1) % 19] | ~mill[(i + 2) % 19]);
                i++;
            } // end while

            i = 0;
            while (i < 19)
            {
                mill[i] = Bits.RotateRight64(a[(7 * i) % 19], (i * (i + 1)) >> 1);
                i++;
            } // end while

            i = 0;
            while (i < 19)
            {
                a[i] = mill[i] ^ mill[(i + 1) % 19] ^ mill[(i + 4) % 19];
                i++;
            } // end while

            a[0] = a[0] ^ 1;

            i = 0;
            while (i < 19)
            {
                mill[i] = a[i];
                i++;
            } // end while

            i = 0;
            while (i < 3)
            {
                mill[i + 13] = mill[i + 13] ^ q[i];
                i++;
            } // end while
        } // end function RoundFunction

    } // end class RadioGatun64
}