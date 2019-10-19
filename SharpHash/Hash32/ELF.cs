using SharpHash.Base;
using SharpHash.Interfaces;
using System;

namespace SharpHash.Hash32
{
    internal class ELF : Hash, IHash32, ITransformBlock
    {
        private UInt32 hash;

        public ELF()
            : base(4, 1)
        { } // end constructor

        override public IHash Clone()
        {
            ELF HashInstance = new ELF();
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
            UInt32 g;
            Int32 i = a_index;

            while (a_length > 0)
            {
                hash = (hash << 4) + a_data[i];
                g = hash & 0xF0000000;

                if (g != 0)
                    hash = hash ^ (g >> 24);

                hash = hash & (~g);
                i++;
                a_length--;
            } // end while
        } // end function TransformBytes

    } // end class ELF
}
