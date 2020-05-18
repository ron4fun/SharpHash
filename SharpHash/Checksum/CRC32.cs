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
    internal sealed class CRC32Polynomials
    {
        public static readonly UInt32 PKZIP = 0x04C11DB7;
        public static readonly UInt32 Castagnoli = 0x1EDC6F41;
    } // end class CRC32Polynomials

    internal class CRC32 : Hash, IChecksum, IBlockHash, IHash32, ITransformBlock
    {
        private ICRC CRCAlgorithm = null;

        public CRC32(UInt64 _poly, UInt64 _Init, bool _refIn, bool _refOut,
            UInt64 _XorOut, UInt64 _check, string[] _Names) : base(4, 1)
        {
            CRCAlgorithm = new CRC(32, _poly, _Init, _refIn, _refOut, _XorOut, _check, _Names);
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
    } // end class CRC32

    internal sealed class CRC32_PKZIP : CRC32
    {
        public CRC32_PKZIP()
            : base(CRC32Polynomials.PKZIP, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0xCBF43926, new string[] { "CRC-32", "CRC-32/ADCCP", "PKZIP" })
        { } // end constructor
    }; // end class CRC32_PKZIP

    internal sealed class CRC32_CASTAGNOLI : CRC32
    {
        public CRC32_CASTAGNOLI()
            : base(CRC32Polynomials.Castagnoli, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0xE3069283, new string[] { "CRC-32C", "CRC-32/ISCSI", "CRC-32/CASTAGNOLI" })
        { } // end constructor
    } // end class CRC32_CASTAGNOLI
}