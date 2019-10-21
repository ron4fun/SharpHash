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

<<<<<<< Updated upstream
        public override void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
	    {
		    CRCAlgorithm.TransformBytes(a_data, a_index, a_length);
=======
        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            CRCAlgorithm.TransformBytes(a_data, a_index, a_length);
>>>>>>> Stashed changes
        } // end function TransformBytes
    } // end class CRC64

    internal sealed class CRC64_ECMA_182 : CRC64
    {
        public CRC64_ECMA_182() : base(CRC64Polynomials.ECMA_182, 0x0000000000000000, false, false, 0x0000000000000000, 0x6C40DF5F0B497347, new string[] { "CRC-64/ECMA" })
        { } // end constructor
    }; // end class _CRC64_ECMA
}