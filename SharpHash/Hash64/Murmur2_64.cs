///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019 - 2020  Mbadiwe Nnaemeka Ronald
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
using System.IO;

namespace SharpHash.Hash64
{
    internal sealed class Murmur2_64 : MultipleTransformNonBlock, IHash64, IHashWithKey, ITransformBlock
    {
        private UInt64 key, working_key;

        static private readonly UInt64 CKEY = 0x0;
        static private readonly UInt64 M = 0xC6A4A7935BD1E995;
        static private readonly Int32 R = 47;

        static private readonly string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        public Murmur2_64()
          : base(8, 8)
        {
            key = CKEY;
        } // end constructor

        override public IHash Clone()
        {
            Murmur2_64 HashInstance = new Murmur2_64();
            HashInstance.key = key;
            HashInstance.working_key = working_key;

            HashInstance.Buffer = new MemoryStream();
            byte[] buf = Buffer.ToArray();
            HashInstance.Buffer.Write(buf, 0, buf.Length);
            HashInstance.Buffer.Position = Buffer.Position;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override public void Initialize()
        {
            working_key = key;
            base.Initialize();
        } // end function Initialize

        override protected unsafe IHashResult ComputeAggregatedBytes(byte[] a_data)
        {
            Int32 Length, current_index;
            UInt64 k, h;

            if (a_data.Empty())
                return new HashResult((UInt64)0);

            Length = a_data.Length;

            fixed (byte* ptr_a_data = a_data)
            {
                h = working_key ^ ((UInt64)Length * M);
                current_index = 0;

                while (Length >= 8)
                {
                    k = Converters.ReadBytesAsUInt64LE((IntPtr)ptr_a_data, current_index);

                    k = k * M;
                    k = k ^ (k >> R);
                    k = k * M;

                    h = h ^ k;
                    h = h * M;

                    current_index += 8;
                    Length -= 8;
                } // end while

                switch (Length)
                {
                    case 7:
                        h = h ^ (((UInt64)(a_data[current_index + 6]) << 48));

                        h = h ^ ((UInt64)(a_data[current_index + 5]) << 40);

                        h = h ^ ((UInt64)(a_data[current_index + 4]) << 32);

                        h = h ^ ((UInt64)(a_data[current_index + 3]) << 24);

                        h = h ^ ((UInt64)(a_data[current_index + 2]) << 16);

                        h = h ^ ((UInt64)(a_data[current_index + 1]) << 8);

                        h = h ^ (UInt64)(a_data[current_index]);

                        h = h * M;
                        break;

                    case 6:
                        h = h ^ ((UInt64)(a_data[current_index + 5]) << 40);

                        h = h ^ ((UInt64)(a_data[current_index + 4]) << 32);

                        h = h ^ ((UInt64)(a_data[current_index + 3]) << 24);

                        h = h ^ ((UInt64)(a_data[current_index + 2]) << 16);

                        h = h ^ ((UInt64)(a_data[current_index + 1]) << 8);

                        h = h ^ (UInt64)(a_data[current_index]);

                        h = h * M;
                        break;

                    case 5:
                        h = h ^ ((UInt64)(a_data[current_index + 4]) << 32);

                        h = h ^ ((UInt64)(a_data[current_index + 3]) << 24);

                        h = h ^ ((UInt64)(a_data[current_index + 2]) << 16);

                        h = h ^ ((UInt64)(a_data[current_index + 1]) << 8);

                        h = h ^ (UInt64)(a_data[current_index]);

                        h = h * M;
                        break;

                    case 4:
                        h = h ^ ((UInt64)(a_data[current_index + 3]) << 24);

                        h = h ^ ((UInt64)(a_data[current_index + 2]) << 16);

                        h = h ^ ((UInt64)(a_data[current_index + 1]) << 8);

                        h = h ^ (UInt64)(a_data[current_index]);

                        h = h * M;
                        break;

                    case 3:
                        h = h ^ ((UInt64)(a_data[current_index + 2]) << 16);

                        h = h ^ ((UInt64)(a_data[current_index + 1]) << 8);

                        h = h ^ (UInt64)(a_data[current_index]);

                        h = h * M;
                        break;

                    case 2:
                        h = h ^ ((UInt64)(a_data[current_index + 1]) << 8);

                        h = h ^ (UInt64)(a_data[current_index]);

                        h = h * M;
                        break;

                    case 1:
                        h = h ^ (UInt64)(a_data[current_index]);

                        h = h * M;
                        break;
                } // end switch

                h = h ^ (h >> R);
                h = h * M;
                h = h ^ (h >> R);
            }

            return new HashResult(h);
        } // end function ComputeAggregatedBytes

        public Int32? KeyLength => 8;

        public byte[] Key
        {
            get => Converters.ReadUInt64AsBytesLE(key);

            set
            {
                if (value.Empty())
                    key = CKEY;
                else
                {
                    if (value.Length != KeyLength)
                        throw new ArgumentHashLibException(string.Format(InvalidKeyLength, KeyLength));

                    unsafe
                    {
                        fixed (byte* bPtr = &value[0])
                        {
                            key = Converters.ReadBytesAsUInt64LE((IntPtr)bPtr, 0);
                        }
                    }
                } // end else
            }
        } // end property Key

    } // end class Murmur2_64
}