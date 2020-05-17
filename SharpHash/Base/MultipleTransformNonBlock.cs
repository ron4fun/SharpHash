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

using SharpHash.Interfaces;
using SharpHash.Utils;
using System;
using System.IO;

namespace SharpHash.Base
{
    internal abstract class MultipleTransformNonBlock : Hash, INonBlockHash
    {
        protected MemoryStream Buffer = null;

        public MultipleTransformNonBlock(Int32 a_hash_size, Int32 a_block_size)
        : base(a_hash_size, a_block_size)
        {
            Buffer = new MemoryStream();
        } // end constructor

        ~MultipleTransformNonBlock()
        {
            Buffer.Flush();
            Buffer.Close();
        } // end destructor

        public override void Initialize()
        {
            Buffer.Flush();
            Buffer.SetLength(0);
        } // end fucntion Initialize

        public override void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            if (a_data.Empty()) return;
            Buffer.Write(a_data, a_index, a_length);
        } // end function TransformBytes

        public override IHashResult TransformFinal()
        {
            IHashResult result = ComputeAggregatedBytes(Aggregate());

            Initialize();

            return result;
        } // end function TransformFinal

        public override IHashResult ComputeBytes(byte[] a_data)
        {
            Initialize();

            return ComputeAggregatedBytes(a_data);
        } // end function ComputeBytes

        protected abstract IHashResult ComputeAggregatedBytes(byte[] a_data);

        private byte[] Aggregate()
        {
            byte[] temp = new byte[0];

            if (Buffer.Length > 0)
            {
                Buffer.Position = 0;
                temp = new byte[Buffer.Length];
                Buffer.Read(temp, 0, (Int32)Buffer.Length);
            } // end if

            return temp;
        } // end function Aggregate
    }
}