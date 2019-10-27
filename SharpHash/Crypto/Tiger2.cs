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

namespace SharpHash.Crypto
{
    internal abstract class Tiger2 : Tiger
    {
        public new static readonly string InvalidTigerHashSize = "Tiger2 HashSize Must be Either 128 bit(16 byte), 160 bit(20 byte) or 192 bit(24 byte)";

        protected Tiger2(Int32 a_hash_size, HashRounds a_rounds)
            : base(a_hash_size, a_rounds)
        { } // end constructor

        protected override void Finish()
        {
            Int32 padindex;

            UInt64 bits = processed_bytes * 8;
            if (buffer.Position < 56)
                padindex = 56 - buffer.Position;
            else
                padindex = 120 - buffer.Position;

            byte[] pad = new byte[padindex + 8];

            pad[0] = 0x80;

            bits = Converters.le2me_64(bits);

            Converters.ReadUInt64AsBytesLE(bits, ref pad, padindex);

            padindex = padindex + 8;

            TransformBytes(pad, 0, padindex);
        } // end function Finish
    } // end class Tiger2

    internal sealed class Tiger2_Base : Tiger2
    {
        public Tiger2_Base(Int32 a_hash_size, HashRounds a_rounds)
            : base(a_hash_size, a_rounds)
        { }

        public override IHash Clone()
        {
            Tiger2_Base HashInstance = new Tiger2_Base(HashSize, GetHashRound(rounds));
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.hash = new UInt64[hash.Length];
            Utils.Utils.memcopy(ref HashInstance.hash, hash, hash.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone
    } // end class Tiger2_Base

    internal sealed class Tiger2_128 : Tiger2
    {
        public override IHash Clone()
        {
            Tiger2_128 HashInstance = new Tiger2_128(HashSizeEnum.HashSize128, GetHashRound(rounds));
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.hash = new UInt64[hash.Length];
            Utils.Utils.memcopy(ref HashInstance.hash, hash, hash.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        private Tiger2_128(HashSizeEnum a_hash_size, HashRounds a_rounds)
            : base((Int32)a_hash_size, a_rounds)
        { }

        public static IHash CreateRound3()
        {
            return new Tiger2_128(HashSizeEnum.HashSize128, HashRounds.Rounds3);
        }

        public static IHash CreateRound4()
        {
            return new Tiger2_128(HashSizeEnum.HashSize128, HashRounds.Rounds4);
        }

        public static IHash CreateRound5()
        {
            return new Tiger2_128(HashSizeEnum.HashSize128, HashRounds.Rounds5);
        }
    } // end class Tiger2_128

    internal sealed class Tiger2_160 : Tiger2
    {
        public override IHash Clone()
        {
            Tiger2_160 HashInstance = new Tiger2_160(HashSizeEnum.HashSize160, GetHashRound(rounds));
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.hash = new UInt64[hash.Length];
            Utils.Utils.memcopy(ref HashInstance.hash, hash, hash.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        private Tiger2_160(HashSizeEnum a_hash_size, HashRounds a_rounds)
            : base((Int32)a_hash_size, a_rounds)
        { }

        public static IHash CreateRound3()
        {
            return new Tiger2_160(HashSizeEnum.HashSize160, HashRounds.Rounds3);
        }

        public static IHash CreateRound4()
        {
            return new Tiger2_160(HashSizeEnum.HashSize160, HashRounds.Rounds4);
        }

        public static IHash CreateRound5()
        {
            return new Tiger2_160(HashSizeEnum.HashSize160, HashRounds.Rounds5);
        }
    } // end class Tiger2_160

    internal sealed class Tiger2_192 : Tiger2
    {
        public override IHash Clone()
        {
            Tiger2_192 HashInstance = new Tiger2_192(HashSizeEnum.HashSize192, GetHashRound(rounds));
            HashInstance.buffer = buffer.Clone();
            HashInstance.processed_bytes = processed_bytes;

            HashInstance.hash = new UInt64[hash.Length];
            Utils.Utils.memcopy(ref HashInstance.hash, hash, hash.Length);

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        private Tiger2_192(HashSizeEnum a_hash_size, HashRounds a_rounds)
            : base((Int32)a_hash_size, a_rounds)
        { }

        public static IHash CreateRound3()
        {
            return new Tiger2_192(HashSizeEnum.HashSize192, HashRounds.Rounds3);
        }

        public static IHash CreateRound4()
        {
            return new Tiger2_192(HashSizeEnum.HashSize192, HashRounds.Rounds4);
        }

        public static IHash CreateRound5()
        {
            return new Tiger2_192(HashSizeEnum.HashSize192, HashRounds.Rounds5);
        }
    } // end class Tiger2_192
}