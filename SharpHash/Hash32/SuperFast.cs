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
using SharpHash.Utils;
using SharpHash.Interfaces;
using System;
using System.IO;

namespace SharpHash.Hash32
{
    internal sealed class SuperFast : MultipleTransformNonBlock, IHash32, ITransformBlock
    {
        public SuperFast()
            : base(4, 4)
        { } // end constructor

        override public IHash Clone()
        {
            SuperFast HashInstance = new SuperFast();

            HashInstance.Buffer = new MemoryStream();
            byte[] buf = Buffer.ToArray();
            HashInstance.Buffer.Write(buf, 0, buf.Length);
            HashInstance.Buffer.Position = Buffer.Position;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override protected IHashResult ComputeAggregatedBytes(byte[] a_data)
        {
            UInt32 hash, tmp, u1;
            Int32 Length, currentIndex, i1, i2;

            if (a_data.Empty())
                return new HashResult((Int32)0);

            Length = a_data.Length;

            hash = (UInt32)Length;
            currentIndex = 0;

            while (Length >= 4)
            {
                i1 = a_data[currentIndex];
                currentIndex++;
                i2 = a_data[currentIndex] << 8;
                currentIndex++;
                hash = (UInt16)(hash + (UInt32)(i1 | i2));
                u1 = (UInt32)(a_data[currentIndex]);
                currentIndex++;
                tmp = (UInt32)(((byte)u1 | a_data[currentIndex] << 8) << 11) ^ hash;
                currentIndex++;
                hash = (hash << 16) ^ tmp;
                hash = hash + (hash >> 11);

                Length -= 4;
            } // end while

            switch (Length)
            {
                case 3:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex];
                    currentIndex++;
                    hash = hash + (UInt16)(i1 | i2 << 8);
                    hash = hash ^ (hash << 16);
                    hash = hash ^ ((UInt32)(a_data[currentIndex]) << 18);
                    hash = hash + (hash >> 11);
                    break;

                case 2:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex];
                    hash = hash + (UInt16)(i1 | i2 << 8);
                    hash = hash ^ (hash << 11);
                    hash = hash + (hash >> 17);
                    break;

                case 1:
                    i1 = a_data[currentIndex];
                    hash = hash + (UInt32)i1;
                    hash = hash ^ (hash << 10);
                    hash = hash + (hash >> 1);
                    break;
            } // end switch

            hash = hash ^ (hash << 3);
            hash = hash + (hash >> 5);
            hash = hash ^ (hash << 4);
            hash = hash + (hash >> 17);
            hash = hash ^ (hash << 25);
            hash = hash + (hash >> 6);

            return new HashResult(hash);
        } // end function ComputeAggregatedBytes
    } // end class SuperFast
}