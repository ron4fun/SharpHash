///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019  Mbadiwe Nnaemeka Ronald
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

        public NullDigest() : base(-1, -1) // Dummy State
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

            try
            {
                Out.Position = 0;
                if (!(res.Length == 0))
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