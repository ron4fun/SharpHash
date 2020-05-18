///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019 - 2020  Mbadiwe Nnaemeka Ronald
/// Github Repository <https://github.com/ron4fun/SharpHash>
///
/// The contents of this file are subject to the
/// Mozilla Public License Version 2.0 (the "License");
/// you may not use this file except in
/// compliance with the License. You may obtain a copy of the License
/// at https://www.mozilla.org/en-US/MPL/2.0/
///
/// Software distributed under the License is distributed on an "AS IS"
/// basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
/// the License for the specific language governing rights and
/// limitations under the License.
///
/// Acknowledgements:
///
/// Thanks to Ugochukwu Mmaduekwe (https://github.com/Xor-el) for his creative
/// development of this library in Pascal/Delphi (https://github.com/Xor-el/HashLib4Pascal).
///
/// Also, I will like to thank Udezue Chukwunwike (https://github.com/IzarchTech) for
/// his contributions to the growth and development of this library.
///
////////////////////////////////////////////////////////////////////////

using SharpHash.Interfaces;
using System;

namespace SharpHash.Base
{
    internal abstract class BlockHash : Hash, IBlockHash
    {
        protected HashBuffer buffer = null;
        protected UInt64 processed_bytes = 0;

        public BlockHash(Int32 a_hash_size, Int32 a_block_size, Int32 a_buffer_size = -1)
        : base(a_hash_size, a_block_size)
        {
            if (a_buffer_size == -1)
                a_buffer_size = a_block_size;

            buffer = new HashBuffer(a_buffer_size);
        } // end constructor

        public override unsafe void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            fixed (byte* ptr_a_data = a_data)
            {
                if (!buffer.IsEmpty)
                {
                    if (buffer.Feed((IntPtr)ptr_a_data, (Int32)a_data.Length, ref a_index, ref a_length, ref processed_bytes))
                        TransformBuffer();
                } // end if

                while (a_length >= buffer.Length)
                {
                    processed_bytes = processed_bytes + (UInt64)buffer.Length;
                    TransformBlock((IntPtr)ptr_a_data, buffer.Length, a_index);
                    a_index = a_index + buffer.Length;
                    a_length = a_length - buffer.Length;
                } // end while

                if (a_length > 0)
                    buffer.Feed((IntPtr)ptr_a_data, (Int32)a_data.Length, ref a_index, ref a_length, ref processed_bytes);
            }
        } // end function TransformBytes

        public override void Initialize()
        {
            buffer.Initialize();
            processed_bytes = 0;
        } // end function Initialize

        public override IHashResult TransformFinal()
        {
            Finish();

            byte[] temp = GetResult();

            Initialize();

            return new HashResult(temp);
        } // end function TransformFinal

        private unsafe void TransformBuffer()
        {
            byte[] temp = buffer.GetBytes();
            fixed (byte* bPtr = temp)
            {
                TransformBlock((IntPtr)bPtr, buffer.Length, 0);
            }
        } // end function TransformBuffer

        protected abstract void Finish();

        protected abstract void TransformBlock(IntPtr a_data,
                Int32 a_data_length, Int32 a_index);

        protected abstract byte[] GetResult();
    }
}