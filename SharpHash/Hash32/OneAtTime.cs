using SharpHash.Base;
using SharpHash.Interfaces;
using System;

namespace SharpHash.Hash32
{
    public class OneAtTime : Hash, IBlockHash, IHash32, ITransformBlock
    {
        private UInt32 hash;

        public OneAtTime()
          : base(4, 1)
        { } // end constructor

        override public IHash Clone()
        {
            OneAtTime HashInstance = new OneAtTime();
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
            hash = hash + (hash << 3);
            hash = hash ^ (hash >> 11);
            hash = hash + (hash << 15);

            IHashResult result = new HashResult(hash);

            Initialize();

            return result;
        } // end function TransformFinal

        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            Int32 i = a_index;

            while (a_length > 0)
            {
                hash = hash + a_data[i];
                hash = hash + (hash << 10);
                hash = hash ^ (hash >> 6);
                i++;
                a_length--;
            } // end while
        } // end function TransformBytes

    } // end class OneAtTime

}
