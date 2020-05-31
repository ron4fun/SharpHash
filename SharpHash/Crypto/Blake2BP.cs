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

using SharpHash.Base;
using SharpHash.Crypto.Blake2BConfigurations;
using SharpHash.Interfaces;
using SharpHash.Interfaces.IBlake2BConfigurations;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    internal sealed class Blake2BP : Hash, ICryptoNotBuiltIn, ITransformBlock
    {
        // had to use the classes directly for performance purposes
        private Blake2B RootHash { get; set; }
        private Blake2B[] LeafHashes = null;
        private byte[] Buffer = null;
        private byte[] Key = null;
        private UInt64 BufferLength { get; set; }

        private static readonly Int32 BlockSizeInBytes = 128;
        private static readonly Int32 OutSizeInBytes = 64;
        private static readonly Int32 ParallelismDegree = 4;

        private struct DataContainer
        {
            public IntPtr PtrData;
            public UInt64 Counter;
        }; // end struct DataContainer

        public Blake2BP(Int32 a_HashSize, byte[] a_Key)
            : base(a_HashSize, BlockSizeInBytes)
        {
            Buffer = new byte[ParallelismDegree * BlockSizeInBytes];
            LeafHashes = new Blake2B[ParallelismDegree];

            Key = a_Key.DeepCopy();

            RootHash = Blake2BPCreateRoot();

            for (Int32 i = 0; i < ParallelismDegree; i++)
                LeafHashes[i] = Blake2BPCreateLeaf((UInt64)i);
        }

        ~Blake2BP()
        {
            Clear();
        }

        public override IHash Clone()
        {
            Blake2BP HashInstance = new Blake2BP(HashSize);

                HashInstance.Key = Key.DeepCopy();
        
            HashInstance.RootHash = (Blake2B)RootHash?.Clone();

            if (LeafHashes != null)
            {
                HashInstance.LeafHashes = new Blake2B[LeafHashes.Length];
                for (Int32 i = 0; i < LeafHashes.Length; i++)
                {
                    HashInstance.LeafHashes[i] = (Blake2B)LeafHashes[i].Clone();
                }
            }

            HashInstance.Buffer = Buffer.DeepCopy();

            HashInstance.BufferLength = BufferLength;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        }

        public override unsafe void Initialize()
        {
            RootHash.Initialize();
            for (Int32 i = 0; i < ParallelismDegree; i++)
            {
                LeafHashes[i].Initialize();
                LeafHashes[i].HashSize = OutSizeInBytes;
            }

            ArrayUtils.ZeroFill(ref Buffer);
            BufferLength = 0;
        }

        public override unsafe void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            UInt64 left, fill, dataLength;
            byte* ptrData = null;
            Int32 i;
            DataContainer ptrDataContainer = new DataContainer();

            if (a_data.Empty()) return;

            dataLength = (UInt64)a_length;

            fixed (byte* ptr = a_data)
            {
                fixed (byte* bufferPtr = Buffer)
                {
                    ptrData = ptr + a_index;

                    left = BufferLength;
                    fill = (UInt64)Buffer.Length - left;

                    if ((left > 0) && (dataLength >= fill))
                    {
                        Utils.Utils.Memmove((IntPtr)(bufferPtr + left), (IntPtr)ptrData, (Int32)fill);

                        for (i = 0; i < ParallelismDegree; i++)
                        {
                            LeafHashes[i].TransformBytes(Buffer, i * BlockSizeInBytes, BlockSizeInBytes);
                        }

                        ptrData += fill;
                        dataLength = dataLength - fill;
                        left = 0;
                    }

                    try
                    {
                        ptrDataContainer.PtrData = (IntPtr)ptrData;
                        ptrDataContainer.Counter = dataLength;
                        DoParallelComputation(ref ptrDataContainer);
                    }
                    catch (Exception)
                    { /* pass */ }

                    ptrData += (dataLength - (dataLength % (UInt64)(ParallelismDegree * BlockSizeInBytes)));
                    dataLength = dataLength % (UInt64)(ParallelismDegree * BlockSizeInBytes);

                    if (dataLength > 0)
                        Utils.Utils.Memmove((IntPtr)(bufferPtr + left), (IntPtr)ptrData, (Int32)dataLength);

                    BufferLength = (UInt32)left + (UInt32)dataLength;
                }
            }
        }

        public override unsafe IHashResult TransformFinal()
        {
            Int32 i;
            UInt64 left;

            byte[][] hash = new byte[ParallelismDegree][];

            for (i = 0; i < hash.Length; i++)
            {
                hash[i] = new byte[OutSizeInBytes];
            }

            for (i = 0; i < ParallelismDegree; i++)
            {
                if (BufferLength > (UInt64)(i * BlockSizeInBytes))
                {
                    left = BufferLength - (UInt64)(i * BlockSizeInBytes);
                    if (left > (UInt64)BlockSizeInBytes)
                        left = (UInt64)BlockSizeInBytes;

                    LeafHashes[i].TransformBytes(Buffer, i * BlockSizeInBytes, (Int32)left);
                }

                hash[i] = LeafHashes[i].TransformFinal().GetBytes();
            }

            for (i = 0; i < ParallelismDegree; i++)
                RootHash.TransformBytes(hash[i], 0, OutSizeInBytes);

            IHashResult result = RootHash.TransformFinal();

            Initialize();

            return result;
        }

        public override string Name
        {
            get
            {
                return String.Format("{0}_{1}", this.GetType().Name, HashSize * 8);
            }
        } // end property Name

        private Blake2BP(Int32 a_HashSize)
            : base(a_HashSize, BlockSizeInBytes)
        { }

        /// <summary>
        /// <br />Blake2B defaults to setting the expected output length <br />
        /// from the <c>HashSize</c> in the <c>Blake2BConfig</c> class. <br />In
        /// some cases, however, we do not want this, as the output length <br />
        /// of these instances is given by <c>Blake2BTreeConfig.InnerSize</c>
        /// instead. <br />
        /// </summary>
        private Blake2B Blake2BPCreateLeafParam(IBlake2BConfig a_Blake2BConfig, IBlake2BTreeConfig a_Blake2BTreeConfig)
        {
            return new Blake2B(a_Blake2BConfig, a_Blake2BTreeConfig);
        }

        private Blake2B Blake2BPCreateLeaf(UInt64 a_Offset)
        {
            IBlake2BConfig blake2BConfig = new Blake2BConfig(HashSize);

            blake2BConfig.Key = Key.DeepCopy();

            IBlake2BTreeConfig blake2BTreeConfig = new Blake2BTreeConfig();
            blake2BTreeConfig.FanOut = (byte)ParallelismDegree;
            blake2BTreeConfig.MaxDepth = 2;
            blake2BTreeConfig.NodeDepth = 0;
            blake2BTreeConfig.LeafSize = 0;
            blake2BTreeConfig.NodeOffset = a_Offset;
            blake2BTreeConfig.InnerHashSize = (byte)OutSizeInBytes;

            if (a_Offset == (UInt64)(ParallelismDegree - 1))
                blake2BTreeConfig.IsLastNode = true;

            return Blake2BPCreateLeafParam(blake2BConfig, blake2BTreeConfig);
        }

        private Blake2B Blake2BPCreateRoot()
        {
            IBlake2BConfig blake2BConfig = new Blake2BConfig(HashSize);

            blake2BConfig.Key = Key.DeepCopy();

            IBlake2BTreeConfig blake2BTreeConfig = new Blake2BTreeConfig();
            blake2BTreeConfig.FanOut = (byte)ParallelismDegree;
            blake2BTreeConfig.MaxDepth = 2;
            blake2BTreeConfig.NodeDepth = 1;
            blake2BTreeConfig.LeafSize = 0;
            blake2BTreeConfig.NodeOffset = 0;
            blake2BTreeConfig.InnerHashSize = (byte)OutSizeInBytes;
            blake2BTreeConfig.IsLastNode = true;

            return new Blake2B(blake2BConfig, blake2BTreeConfig, false);
        }

        private unsafe void ParallelComputation(Int32 Idx, ref DataContainer a_DataContainer)
        {
            byte[] temp = new byte[BlockSizeInBytes];

            byte* ptrData = (byte*)a_DataContainer.PtrData;

            UInt64 counter = a_DataContainer.Counter;

            ptrData += (Idx * BlockSizeInBytes);

            while (counter >= (UInt64)(ParallelismDegree * BlockSizeInBytes))
            {
                fixed (byte* tempPtr = temp)
                {
                    Utils.Utils.Memmove((IntPtr)tempPtr, (IntPtr)ptrData, BlockSizeInBytes);

                    LeafHashes[Idx].TransformBytes(temp, 0, BlockSizeInBytes);

                    ptrData += ((UInt64)(ParallelismDegree * BlockSizeInBytes));
                    counter = counter - (UInt64)(ParallelismDegree * BlockSizeInBytes);
                }
            }
        }

        private void DoParallelComputation(ref DataContainer a_DataContainer)
        {
            for (Int32 i = 0; i < ParallelismDegree; i++)
                ParallelComputation(i, ref a_DataContainer);
        }

        private void Clear()
        {
            ArrayUtils.ZeroFill(ref Key);
        }

    } // end class Blake2BP
}
