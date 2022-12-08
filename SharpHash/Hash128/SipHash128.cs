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
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Hash64
{
    internal abstract class SipHash128 : SipHash
    {
        protected SipHash128(Int32 compression_rounds, Int32 finalization_rounds) 
            : base(16, 8)
        {
            cr = compression_rounds;
            fr = finalization_rounds;
        } // end constructor

        override public void Initialize()
        {
            base.Initialize();
            v1 ^= GetMagicXor();
        } // end function Initialize

        override public IHashResult TransformFinal()
        {
            UInt64 finalBlock = ProcessFinalBlock();
            v3 ^= finalBlock;
            CompressTimes(cr);
            v0 ^= finalBlock;
            v2 ^= GetMagicXor();
            CompressTimes(fr);


            byte[] BufferByte = new byte[HashSize];
            Converters.ReadUInt64AsBytesLE(v0 ^ v1 ^ v2 ^ v3, ref BufferByte, 0);
            v1 ^= 0xDD;
            CompressTimes(fr);
            Converters.ReadUInt64AsBytesLE(v0 ^ v1 ^ v2 ^ v3, ref BufferByte, 8);

            IHashResult result = new HashResult(BufferByte);
            Initialize();
            return result;
        } // end function TransformFinal

        override protected byte GetMagicXor() => 0xEE;

    }; // end class SipHash128


    internal sealed class SipHash128_2_4 : SipHash128
    {
        public SipHash128_2_4()
            : base(2, 4)
        {} // end constructor

        public override IHash Clone()
        {
            SipHash128_2_4 HashInstance = new SipHash128_2_4();
            HashInstance.v0 = v0;
            HashInstance.v1 = v1;
            HashInstance.v2 = v2;
            HashInstance.v3 = v3;
            HashInstance.key0 = key0;
            HashInstance.key1 = key1;
            HashInstance.total_length = total_length;
            HashInstance.cr = cr;
            HashInstance.fr = fr;
            HashInstance.idx = idx;

            HashInstance.buf = buf.DeepCopy();

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

    } // end class SipHash128_2_4

}