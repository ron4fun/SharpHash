using SharpHash.Base;
using SharpHash.Interfaces;
using System;

namespace SharpHash.Hash32
{
    public class AP : Hash, IHash32, ITransformBlock
    {
        private UInt32 hash;
        private Int32 index;

        public AP()
            : base(4, 1)
        {} // end constructor

        override public IHash Clone()
    	{
            AP HashInstance = new AP();
            HashInstance.hash = hash;
		    HashInstance.index = index;

            HashInstance.BufferSize = BufferSize;

		    return HashInstance;
	    } // end function Clone

        override public void Initialize()
        {
            hash = 0xAAAAAAAA;
            index = 0;
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
                if ((index & 1) == 0)
                    hash = hash ^ ((hash << 7) ^ a_data[i] * (hash >> 3));
                else
                    hash = hash ^ (~((hash << 11) ^ a_data[i] ^ (hash >> 5)));

                index++;
                i++;
                a_length--;
            } // end while
        } // end function TransformBytes

    } // end class AP

}
