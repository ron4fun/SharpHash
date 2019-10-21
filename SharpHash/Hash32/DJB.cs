using SharpHash.Base;
using SharpHash.Interfaces;
using System;

namespace SharpHash.Hash32
{
    internal sealed class DJB : Hash, IHash32, ITransformBlock
    {
        private UInt32 hash;

        public DJB()
            : base(4, 1)
        { } // end constructor

        override public IHash Clone()
        {
            DJB HashInstance = new DJB();
            HashInstance.hash = hash;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override public void Initialize()
        {
            hash = 5381;
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
                hash = ((hash << 5) + hash) + a_data[i];
                i++;
                a_length--;
            } // end while
        } // end function TransformBytes
    } // end class
}