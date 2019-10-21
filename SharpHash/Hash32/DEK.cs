using SharpHash.Base;
using SharpHash.Interfaces;
using System;
using System.IO;

namespace SharpHash.Hash32
{
    internal sealed class DEK : MultipleTransformNonBlock, IHash32, ITransformBlock
    {
        public DEK()
            : base(4, 1)
        { } // end constructor

        override public IHash Clone()
        {
            DEK HashInstance = new DEK();

            HashInstance.Buffer = new MemoryStream();
            byte[] buf = Buffer.ToArray();
            HashInstance.Buffer.Write(buf, 0, buf.Length);
            HashInstance.Buffer.Position = Buffer.Position;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override protected IHashResult ComputeAggregatedBytes(byte[] a_data)
        {
            UInt32 hash = 0;

            if (!(a_data == null || a_data.Length == 0))
            {
                hash = (UInt32)a_data.Length;

                for (Int32 i = 0; i < a_data.Length; i++)
                    hash = Utils.Bits.RotateLeft32(hash, 5) ^ a_data[i];
            } // end if

            return new HashResult(hash);
        } // end function ComputeAggregatedBytes
    } // end class DEK
}