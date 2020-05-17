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

using System;
using SharpHash.Utils;
using SharpHash.Interfaces.IBlake2BConfigurations;

namespace SharpHash.Crypto.Blake2BConfigurations
{
    public sealed class Blake2BTreeConfig : IBlake2BTreeConfig
    {
        public static readonly string InvalidFanOutParameter = "FanOut Value Should be Between [0 .. 255] for Blake2B";
        //public static readonly string InvalidMaxDepthParameter = "MaxDepth Value Should be Between [1 .. 255] for Blake2B";
        public static readonly string InvalidNodeDepthParameter = "NodeDepth Value Should be Between [0 .. 255] for Blake2B";
        public static readonly string InvalidInnerHashSizeParameter = "InnerHashSize Value Should be Between [0 .. 64] for Blake2B";
        public static readonly string InvalidNodeOffsetParameter = "NodeOffset Value Should be Between [0 .. (2^64-1)] for Blake2B";

        private byte fanOut;
        public byte FanOut
        {
            get => fanOut;
            set
            {
                ValidateFanOut(value);
                fanOut = value;
            }
        }

        public byte MaxDepth { get; set; }

        private byte nodeDepth;
        public byte NodeDepth
        {
            get => nodeDepth;
            set
            {
                ValidateNodeDepth(value);
                nodeDepth = value;
            }
        }

        private byte innerHashSize;
        public byte InnerHashSize
        {
            get => innerHashSize;
            set
            {
                ValidateInnerHashSize(value);
                innerHashSize = value;
            }
        }

        public UInt32 LeafSize { get; set; }

        private UInt64 nodeOffset;
        public UInt64 NodeOffset
        {
            get => nodeOffset;
            set
            {
                ValidateNodeOffset(value);
                nodeOffset = value;
            }
        }

        public bool IsLastNode { get; set; }

        public Blake2BTreeConfig()
        {
            FanOut = 0;
            MaxDepth = 0;
            LeafSize = 64;
            NodeOffset = 0;
            NodeDepth = 0;
            InnerHashSize = 64;
            IsLastNode = false;
        }

        public static IBlake2BTreeConfig GetSequentialTreeConfig()
        {
            Blake2BTreeConfig result = new Blake2BTreeConfig();
            result.FanOut = 1;
            result.MaxDepth = 1;
            result.LeafSize = 0;
            result.NodeOffset = 0;
            result.NodeDepth = 0;
            result.InnerHashSize = 0;
            result.IsLastNode = false;

            return result;
        }

	    public IBlake2BTreeConfig Clone()
	    {
		    Blake2BTreeConfig result = new Blake2BTreeConfig();
            result.FanOut = FanOut;
		    result.InnerHashSize = InnerHashSize;
		    result.MaxDepth = MaxDepth;
		    result.NodeDepth = NodeDepth;
		    result.LeafSize = LeafSize;
		    result.NodeOffset = NodeOffset;
		    result.IsLastNode = IsLastNode;

		    return result;
	    }

        private void ValidateFanOut(byte a_FanOut)
        {
            if (!(a_FanOut >= 0 && a_FanOut <= 255))
                throw new ArgumentInvalidHashLibException(InvalidFanOutParameter);
        }

        private void ValidateInnerHashSize(byte a_InnerHashSize)
        {
            if (!(a_InnerHashSize >= 0 && a_InnerHashSize <= 64))
                throw new ArgumentInvalidHashLibException(InvalidInnerHashSizeParameter);
        }

        //private void ValidateMaxDepth(byte a_MaxDepth)
        //{
        //    if (!(a_MaxDepth > 0 && a_MaxDepth <= 255))
        //        throw new ArgumentInvalidHashLibException(InvalidMaxDepthParameter);
        //}

        private void ValidateNodeDepth(byte a_NodeDepth)
        {
            if (!(a_NodeDepth >= 0 && a_NodeDepth <= 255))
                throw new ArgumentInvalidHashLibException(InvalidNodeDepthParameter);
        }

        private void ValidateNodeOffset(UInt64 a_NodeOffset)
        {
            if (a_NodeOffset > UInt64.MaxValue)
                throw new ArgumentInvalidHashLibException(InvalidNodeOffsetParameter);
        }

    } // end class Blake2BTreeConfig
}
