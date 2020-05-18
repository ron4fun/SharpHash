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

namespace SharpHash.Hash32
{
    internal sealed class Murmur2 : MultipleTransformNonBlock, IHash32, IHashWithKey, ITransformBlock
    {
        private UInt32 key, working_key, h;

        static private readonly UInt32 CKEY = 0x0;
        static private readonly UInt32 M = 0x5BD1E995;
        static private readonly Int32 R = 24;

        static private readonly string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        public Murmur2()
          : base(4, 4)
        { } // end constructor

        override public IHash Clone()
        {
            Murmur2 HashInstance = new Murmur2();
            HashInstance.key = key;
            HashInstance.working_key = working_key;
            HashInstance.h = h;

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

        override protected IHashResult ComputeAggregatedBytes(byte[] a_data)
        {
            return new HashResult(InternalComputeBytes(a_data));
        } // end function ComputeAggregatedBytes

        private Int32 InternalComputeBytes(byte[] a_data)
        {
            Int32 Length, current_index;
            UInt32 k;

            if (a_data.Empty())
                return 0;

            Length = a_data.Length;

            h = working_key ^ (UInt32)Length;
            current_index = 0;

            unsafe
            {
                fixed (byte* ptr_a_data = a_data)
                {
                    while (Length >= 4)
                    {
                        k = Converters.ReadBytesAsUInt32LE((IntPtr)ptr_a_data, current_index);

                        TransformUInt32Fast(k);
                        current_index += 4;
                        Length -= 4;
                    } // end while

                    switch (Length)
                    {
                        case 3:
                            h = h ^ (UInt32)(a_data[current_index + 2] << 16);
                            h = h ^ (UInt32)(a_data[current_index + 1] << 8);
                            h = h ^ (a_data[current_index]);
                            h = h * M;
                            break;

                        case 2:
                            h = h ^ (UInt32)(a_data[current_index + 1] << 8);
                            h = h ^ (a_data[current_index]);
                            h = h * M;
                            break;

                        case 1:
                            h = h ^ (a_data[current_index]);
                            h = h * M;
                            break;
                    } // end switch
                }
            }

            h = h ^ (h >> 13);

            h = h * M;
            h = h ^ (h >> 15);

            return (Int32)h;
        } // end function InternalComputeBytes

        private void TransformUInt32Fast(UInt32 a_data)
        {
            a_data = a_data * M;
            a_data = a_data ^ (a_data >> R);
            a_data = a_data * M;

            h = h * M;
            h = h ^ a_data;
        } // end function TransformUInt32Fast

        public Int32? KeyLength
        {
            get => 4;
        } // end property KeyLength

        public byte[] Key
        {
            get => Converters.ReadUInt32AsBytesLE(key);
            
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
                            key = Converters.ReadBytesAsUInt32LE((IntPtr)bPtr, 0);
                        }
                    }
                } // end else
            }
        } // end property Key
    } // end class Murmur2
}