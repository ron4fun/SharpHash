using SharpHash.Base;
using SharpHash.Interfaces;
using System;
using System.IO;

namespace SharpHash.NullDigest
{
    public class NullDigest : Hash, ITransformBlock
    {
        private MemoryStream Out = null;

        public NullDigest() : base(0,-1) // Dummy State
        {
            Out = new MemoryStream();
        } // end constructor

        ~NullDigest()
        {
            Out.Flush();
            Out.Close();
        }

        override public IHash Clone()
    	{
            NullDigest HashInstance = new NullDigest();

            byte[] buf = Out.ToArray();
            HashInstance.Out.Write(buf, 0, buf.Length);

            HashInstance.Out.Position = 0;

            HashInstance.SetBufferSize(GetBufferSize());

		    return HashInstance;
	    }

        override public void Initialize()
        {
            Out.Flush();
            Out.SetLength(0); // Reset stream

            hash_size = 0;
            block_size = 0;
        } // end function Initialize

        override public IHashResult TransformFinal()
        {
            Int32 size = (Int32)Out.Length;

            byte[] res = new byte[size];
            Array.Resize(ref res, size);

            try
            {
                if (!(res == null || res.Length == 0))
                    Out.Read(res, 0, size);    
            } // end try
            finally
            {
                Initialize();
            } // end finally

            IHashResult result = new HashResult(res);

            return result;
        } // end function TransformFinal

        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            if (!(a_data == null || a_data.Length == 0))
            {
                Out.Write(a_data, a_index, a_length);
            }

            //hash_size = Out.Length;
        } // end function TransformBytes

    }
}
