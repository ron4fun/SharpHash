using SharpHash.Base;
using SharpHash.Interfaces;
using System;
using System.Collections.Generic;

namespace SharpHash.Hash32
{
    public class DEK : MultipleTransformNonBlock, IHash32, ITransformBlock
    {
        public DEK()
            : base(4, 1)
        { } // end constructor

        override public IHash Clone()
        {
            DEK HashInstance = new DEK();
            
            HashInstance._list = new List<byte[]>(_list);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override protected IHashResult ComputeAggregatedBytes(byte[] a_data)
	    {
		    UInt32 hash = (UInt32)a_data.Length;

		    for (Int32 i = 0; i < a_data.Length; i++)
			    hash = Utils.Bits.RotateLeft32(hash, 5) ^ a_data[i];
		
		    return new HashResult(hash);
	    } // end function ComputeAggregatedBytes

    } // end class DEK
}
