using SharpHash.Base;
using SharpHash.Interfaces;
using System;

namespace SharpHash.Hash32
{
    public class RS : Hash, IBlockHash, IHash32, ITransformBlock
    {
        private UInt32 a, hash;
        static private UInt32 b = 378551;

        public RS()
          : base(4, 1)
        { } // end constructor

        override public IHash Clone()
        {
            RS HashInstance = new RS();
            HashInstance.hash = hash;
            HashInstance.a = a;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override public void Initialize()
        {
            hash = 0;
            a = 63689;
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
                hash = (hash * a) + a_data[i];
                a = a * b;
                i++;
                a_length--;
            } // end while
        } // end function TransformBytes

    } // end class RS
}
