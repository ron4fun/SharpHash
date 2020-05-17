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
using System;

namespace SharpHash.Checksum
{
    internal sealed class Adler32 : Hash, IChecksum, IBlockHash, IHash32, ITransformBlock
    {
        private const UInt32 MOD_ADLER = 65521;
        private UInt32 a = 1, b = 0;

        public Adler32()
            : base(4, 1)
        { } // end constructor

        public override IHash Clone()
        {
            Adler32 HashInstance = new Adler32();
            HashInstance.a = a;
            HashInstance.b = b;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        public override void Initialize()
        {
            a = 1;
            b = 0;
        } // end function Initialize

        public override IHashResult TransformFinal()
        {
            IHashResult result = new HashResult((Int32)((b << 16) | a));

            Initialize();

            return result;
        } // end function TransformFinal

        public override void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            Int32 n;

            // lifted from PngEncoder Adler32.cs

            while (a_length > 0)
            {
                // We can defer the modulo operation:
                // a maximally grows from 65521 to 65521 + 255 * 3800
                // b maximally grows by3800 * median(a) = 2090079800 < 2^31
                n = 3800;
                if (n > a_length)
                    n = a_length;

                a_length = a_length - n;

                while ((n - 1) >= 0)
                {
                    a = (a + a_data[a_index]);
                    b = (b + a);
                    a_index++;
                    n--;
                } // end while

                a = a % MOD_ADLER;
                b = b % MOD_ADLER;
            } // end while
        } // end function TransformBlock
    }
}