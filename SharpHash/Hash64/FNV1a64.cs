using SharpHash.Base;
using SharpHash.Interfaces;
using System;

namespace SharpHash.Hash64
{
    public class FNV1a64 : Hash, IBlockHash, IHash64, ITransformBlock
    {
        private UInt64 hash;

        public FNV1a64()
            : base(8, 1)
        { } // end constructor

        override public IHash Clone()
        {
            FNV1a64 HashInstance = new FNV1a64();
            HashInstance.hash = hash;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override public void Initialize()
        {
            hash = 14695981039346656037;
        } // end function Initialize

        override public IHashResult TransformFinal()
        {
            IHashResult result = new HashResult(hash);

            Initialize();

            return result;
        } // end function TransformFinal

        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            Int32 i = a_index;

            while (a_length > 0)
            {
                hash = (hash ^ a_data[i]) * 1099511628211;
                i++;
                a_length--;
            } // end while
        } // end function TransformBytes

    } // end class FNV1a64
}
