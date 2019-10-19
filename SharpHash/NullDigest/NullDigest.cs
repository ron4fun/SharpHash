using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;
using System.IO;

namespace SharpHash
{
    internal sealed class NullDigest : Hash, ITransformBlock
    {
        private MemoryStream Out = null;

        private static readonly string HashSizeNotImplemented = "HashSize Not Implemented For \"{0}\"";
        private static readonly string BlockSizeNotImplemented = "BlockSize Not Implemented For \"{0}\"";

        public NullDigest() : base(-1,-1) // Dummy State
        {
            Out = new MemoryStream();
        } // end constructor

        ~NullDigest()
        {
            Out.Flush();
            Out.Close();
        }

        override public Int32 BlockSize
        {
            get
            {
                throw new NotImplementedHashLibException(String.Format(BlockSizeNotImplemented, Name));
            }
        } // end property BlockSize

        override public Int32 HashSize
        {
            get
            {
                throw new NotImplementedHashLibException(String.Format(HashSizeNotImplemented, Name));
            }
        } // end property HashSize

        override public IHash Clone()
    	{
            NullDigest HashInstance = new NullDigest();

            byte[] buf = Out.ToArray();
            HashInstance.Out.Write(buf, 0, buf.Length);

            HashInstance.Out.Position = Out.Position;

            HashInstance.BufferSize = BufferSize;

		    return HashInstance;
	    }

        override public void Initialize()
        {
            Out.Flush();
            Out.SetLength(0); // Reset stream
        } // end function Initialize

        override public IHashResult TransformFinal()
        {
            Int32 size = (Int32)Out.Length;

            byte[] res = new byte[size];
            Array.Resize(ref res, size);

            try
            {
                Out.Position = 0;
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
            } // end if
        } // end function TransformBytes

    }
}
