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
using SharpHash.Crypto.Blake2SConfigurations;
using SharpHash.Interfaces;
using SharpHash.Interfaces.IBlake2SConfigurations;
using SharpHash.Utils;
using System;

namespace SharpHash.Crypto
{
    internal sealed class Blake2SP : Hash, ICryptoNotBuildIn, ITransformBlock
    {
        // had to use the classes directly for performance purposes
        private Blake2S RootHash { get; set; }
        private Blake2S[] LeafHashes = null;
        private byte[] Buffer = null;
        private byte[] Key = null;
        private UInt64 BufferLength { get; set; }

        private static readonly Int32 BlockSizeInBytes = 64;
        private static readonly Int32 OutSizeInBytes = 32;
        private static readonly Int32 ParallelismDegree = 8;

        private struct DataContainer
        {
            public IntPtr PtrData;
            public UInt64 Counter;
        }; // end struct DataContainer
            
        public Blake2SP(Int32 a_HashSize, byte[] a_Key)
            : base(a_HashSize, BlockSizeInBytes)
        {
            Buffer = new byte[ParallelismDegree * BlockSizeInBytes];
            LeafHashes = new Blake2S[ParallelismDegree];

            Key = a_Key.DeepCopy();
           
            RootHash = Blake2SPCreateRoot();

            for (Int32 i = 0; i < ParallelismDegree; i++)
                LeafHashes[i] = Blake2SPCreateLeaf((UInt64)i);
        }

        ~Blake2SP()
        {
            Clear();
        }

        public override IHash Clone()
        {
            Blake2SP HashInstance = new Blake2SP(HashSize);

            HashInstance.Key = Key.DeepCopy();

            HashInstance.RootHash = (Blake2S)RootHash?.Clone();

            if (LeafHashes != null)
            {
                HashInstance.LeafHashes = new Blake2S[LeafHashes.Length];
                for (Int32 i = 0; i < LeafHashes.Length; i++)
                {
                    HashInstance.LeafHashes[i] = (Blake2S)LeafHashes[i].Clone();
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

        private Blake2SP(Int32 a_HashSize)
            : base(a_HashSize, BlockSizeInBytes)
        { }

        /// <summary>
        /// <br />Blake2S defaults to setting the expected output length <br />
        /// from the <c>HashSize</c> in the <c>Blake2SConfig</c> class. <br />In
        /// some cases, however, we do not want this, as the output length <br />
        /// of these instances is given by <c>Blake2STreeConfig.InnerSize</c>
        /// instead. <br />
        /// </summary>
        private Blake2S Blake2SPCreateLeafParam(IBlake2SConfig a_Blake2SConfig, IBlake2STreeConfig a_Blake2STreeConfig)
        {
            return new Blake2S(a_Blake2SConfig, a_Blake2STreeConfig);
        }

        private Blake2S Blake2SPCreateLeaf(UInt64 a_Offset)
        {
            IBlake2SConfig blake2SConfig = new Blake2SConfig(HashSize);

            blake2SConfig.Key = Key.DeepCopy();

            IBlake2STreeConfig blake2STreeConfig = new Blake2STreeConfig();
            blake2STreeConfig.FanOut = (byte)ParallelismDegree;
            blake2STreeConfig.MaxDepth = 2;
            blake2STreeConfig.NodeDepth = 0;
            blake2STreeConfig.LeafSize = 0;
            blake2STreeConfig.NodeOffset = a_Offset;
            blake2STreeConfig.InnerHashSize = (byte)OutSizeInBytes;

            if (a_Offset == (UInt64)(ParallelismDegree - 1))
                blake2STreeConfig.IsLastNode = true;

            return Blake2SPCreateLeafParam(blake2SConfig, blake2STreeConfig);
        }

        private Blake2S Blake2SPCreateRoot()
        {
            IBlake2SConfig blake2SConfig = new Blake2SConfig(HashSize);

            blake2SConfig.Key = Key.DeepCopy();

            IBlake2STreeConfig blake2STreeConfig = new Blake2STreeConfig();
            blake2STreeConfig.FanOut = (byte)ParallelismDegree;
            blake2STreeConfig.MaxDepth = 2;
            blake2STreeConfig.NodeDepth = 1;
            blake2STreeConfig.LeafSize = 0;
            blake2STreeConfig.NodeOffset = 0;
            blake2STreeConfig.InnerHashSize = (byte)OutSizeInBytes;
            blake2STreeConfig.IsLastNode = true;

            return new Blake2S(blake2SConfig, blake2STreeConfig, false);
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

    } // end class Blake2SP
}
