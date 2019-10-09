using SharpHash.Base;
using SharpHash.Interfaces;
using System;

namespace SharpHash.Checksum
{
    public class Adler32 : Hash, IChecksum, IBlockHash, IHash32, ITransformBlock
    {
        static private UInt32 MOD_ADLER = 65521;
        private UInt32 a = 1, b = 0;

        public Adler32() 
            : base(4, 1)
        {} // end constructor

        override public IHash Clone()
    	{
            Adler32 HashInstance = new Adler32();
            HashInstance.a = a;
		    HashInstance.b = b;

            HashInstance.SetBufferSize(GetBufferSize());

		    return HashInstance;
	    } // end function Clone

        override public void Initialize()
        {
            a = 1;
            b = 0;
        } // end function Initialize

        override public IHashResult TransformFinal()
        {
            IHashResult result = new HashResult((Int32)((b << 16) | a));

            Initialize();

            return result;
        } // end function TransformFinal

        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
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
