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
using System;

namespace SharpHash.Checksum
{
    internal sealed class CRC64Polynomials
    {
        static public readonly UInt64 ECMA_182 = 0x42F0E1EBA9EA3693;
    }; // end class CRC64Polynomials

    internal class CRC64 : Hash, IChecksum, IBlockHash, IHash64, ITransformBlock
    {
        private ICRC CRCAlgorithm = null;

        public CRC64(UInt64 _poly, UInt64 _Init, bool _refIn, bool _refOut,
            UInt64 _XorOut, UInt64 _check, string[] _Names)
            : base(8, 1)
        {
            CRCAlgorithm = new CRC(64, _poly, _Init, _refIn, _refOut, _XorOut, _check, _Names);
        } // end constructor

        public override void Initialize()
        {
            CRCAlgorithm.Initialize();
        } // end function Initialize

        public override IHashResult TransformFinal()
        {
            return CRCAlgorithm.TransformFinal();
        } // end function TransformFinal

        public override void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            CRCAlgorithm.TransformBytes(a_data, a_index, a_length);
        } // end function TransformBytes
    } // end class CRC64

    internal sealed class CRC64_ECMA_182 : CRC64
    {
        public CRC64_ECMA_182() : base(CRC64Polynomials.ECMA_182, 0x0000000000000000, false, false, 0x0000000000000000, 0x6C40DF5F0B497347, new string[] { "CRC-64/ECMA" })
        { } // end constructor
    }; // end class _CRC64_ECMA
}