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
using System;

namespace SharpHash.Hash32
{
    internal sealed class PJW : Hash, IHash32, ITransformBlock
    {
        static private readonly UInt32 UInt32MaxValue = 4294967295;
        static private readonly UInt32 BitsInUnsignedInt = sizeof(UInt32) * 8;
        static private readonly UInt32 threeQuarters = (BitsInUnsignedInt * 3) >> 2;
        static private readonly UInt32 oneEighth = BitsInUnsignedInt >> 3;
        static private readonly UInt32 highBits = UInt32MaxValue << (Int32)(BitsInUnsignedInt - oneEighth);

        private UInt32 hash;

        public PJW()
            : base(4, 1)
        { } // end constructor

        override public IHash Clone()
        {
            PJW HashInstance = new PJW();
            HashInstance.hash = hash;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override public void Initialize()
        {
            hash = 0;
        } // end function Initialize

        override public IHashResult TransformFinal()
        {
            IHashResult result = new HashResult(hash);

            Initialize();

            return result;
        } // end function TransformFinal

        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            UInt32 test;
            Int32 i = a_index;

            while (a_length > 0)
            {
                hash = (hash << (Int32)oneEighth) + a_data[i];
                test = hash & highBits;
                if (test != 0)
                    hash = ((hash ^ (test >> (Int32)threeQuarters)) & (~highBits));
                i++;
                a_length--;
            } // end while
        } // end function TransformBytes
    } // end class PJW
}