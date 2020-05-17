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
    internal sealed class DEK : MultipleTransformNonBlock, IHash32, ITransformBlock
    {
        public DEK()
            : base(4, 1)
        { } // end constructor

        override public IHash Clone()
        {
            DEK HashInstance = new DEK();

            HashInstance.Buffer = new MemoryStream();
            byte[] buf = Buffer.ToArray();
            HashInstance.Buffer.Write(buf, 0, buf.Length);
            HashInstance.Buffer.Position = Buffer.Position;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override protected IHashResult ComputeAggregatedBytes(byte[] a_data)
        {
            UInt32 hash = 0;

            if (!a_data.Empty())
            {
                hash = (UInt32)a_data.Length;

                for (Int32 i = 0; i < a_data.Length; i++)
                    hash = Utils.Bits.RotateLeft32(hash, 5) ^ a_data[i];
            } // end if

            return new HashResult(hash);
        } // end function ComputeAggregatedBytes
    } // end class DEK
}