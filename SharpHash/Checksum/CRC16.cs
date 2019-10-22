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
using System;

namespace SharpHash.Checksum
{
    internal sealed class CRC16Polynomials
    {
        public static readonly UInt16 BUYPASS = 0x8005;
    }; // end class CRC16Polynomials

    internal class CRC16 : Hash, IChecksum, IBlockHash, IHash16, ITransformBlock
    {
        private ICRC CRCAlgorithm = null;

        public CRC16(UInt64 _poly, UInt64 _Init, bool _refIn, bool _refOut,
            UInt64 _XorOut, UInt64 _check, string[] _Names)
        : base(2, 1)
        {
            CRCAlgorithm = new CRC(16, _poly, _Init, _refIn, _refOut, _XorOut, _check, _Names);
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
    } // end class CRC16

    internal sealed class CRC16_BUYPASS : CRC16
    {
        public CRC16_BUYPASS()
            : base(CRC16Polynomials.BUYPASS, 0x0000, false, false, 0x0000, 0xFEE8, new string[] { "CRC-16/BUYPASS", "CRC-16/VERIFONE" })
        { } // end constructor
    } // end class CRC16_BUYPASS
}