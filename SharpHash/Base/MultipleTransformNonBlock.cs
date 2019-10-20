using SharpHash.Interfaces;
using System;
using System.Collections.Generic;
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

        override public void Initialize()
        {
            Buffer.Flush();
            Buffer.SetLength(0);
        } // end fucntion Initialize

        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
	    {
            Buffer.Write(a_data, a_index, a_length);
        } // end function TransformBytes

        override public IHashResult TransformFinal()
        {
            IHashResult result = ComputeAggregatedBytes(Aggregate());

            Initialize();

            return result;
        } // end function TransformFinal

        override public IHashResult ComputeBytes(byte[] a_data)
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
