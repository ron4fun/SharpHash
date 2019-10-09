using SharpHash.Interfaces;
using System;
using System.Collections.Generic;

namespace SharpHash.Base
{
    public abstract class MultipleTransformNonBlock : Hash, INonBlockHash
    {
        protected List<byte[]> _list;

        public MultipleTransformNonBlock(Int32 a_hash_size, Int32 a_block_size)
		: base(a_hash_size, a_block_size)
        {
            _list = new List<byte[]>();
        } // end constructor

        override public void Initialize()
        {
            _list.Clear();
        } // end fucntion Initialize

        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
	    {
            if (a_data == null || a_data.Length == 0)
            {
                _list.Add(new byte[] { });
                return;
            } // end if

            unsafe
            {
                byte[] temp = new byte[a_length];

                fixed (byte* DestPtr = &temp[0], srcPtr = &a_data[a_index])
                {
                    Utils.Utils.memcopy((IntPtr)DestPtr, (IntPtr)srcPtr, a_length);                    
                }

                _list.Add(temp);
            }
	    } // end function TransformBytes

        override public IHashResult TransformFinal()
        {
            IHashResult result = ComputeAggregatedBytes(Aggregate());

            Initialize();

            return result;
        } // end function TransformFinal

        override public IHashResult ComputeBytes(byte[] a_data)
        {
            Initialize();

            return ComputeAggregatedBytes(a_data);
        } // end function ComputeBytes

	    protected abstract IHashResult ComputeAggregatedBytes(byte[] a_data);

        private byte[] Aggregate()
        {
            UInt32 sum = 0;
            Int32 index = 0;

            for (Int32 i = 0; i < _list.Count; i++)
	        {
                sum = sum + (UInt32)(_list)[i].Length;
            } // end for

            byte[] result = new byte[sum];

            for (Int32 i = 0; i < _list.Count; i++) 
	        {
                unsafe
                {
                    fixed (byte* dPtr = &result[index], sPtr = &(_list)[i][0])
                    {
                        Utils.Utils.memmove((IntPtr)dPtr, (IntPtr)sPtr, (_list)[i].Length * sizeof(byte));
                    }
                }
                
                index = index + (_list)[i].Length;
            } // end for

            return result;
        } // end function Aggregate

    }
}
