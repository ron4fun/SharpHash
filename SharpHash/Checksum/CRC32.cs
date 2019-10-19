using SharpHash.Base;
using SharpHash.Interfaces;
using System;

namespace SharpHash.Checksum
{
    internal abstract class CRC32Polynomials
    {
	    static public readonly UInt32 PKZIP = 0x04C11DB7;
        static public readonly UInt32 Castagnoli = 0x1EDC6F41;
    } // end class CRC32Polynomials

    internal class CRC32: Hash, IChecksum, IBlockHash, IHash32, ITransformBlock
    {
        private ICRC CRCAlgorithm = null;

        public CRC32(UInt64 _poly, UInt64 _Init, bool _refIn, bool _refOut, 
            UInt64 _XorOut, UInt64 _check, string[] _Names) : base(4, 1)
        {
            CRCAlgorithm = new CRC(32, _poly, _Init, _refIn, _refOut, _XorOut, _check, _Names);
        } // end constructor

        override public void Initialize()
        {
            CRCAlgorithm.Initialize();
        } // end function Initialize

        override public IHashResult TransformFinal()
        {
            return CRCAlgorithm.TransformFinal();
        } // end function TransformFinal

        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
	    {
		    CRCAlgorithm.TransformBytes(a_data, a_index, a_length);
        } // end function TransformBytes

    } // end class CRC32


    internal class CRC32_PKZIP : CRC32
    {
        public CRC32_PKZIP() 
            : base(CRC32Polynomials.PKZIP, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0xCBF43926, new string[] { "CRC-32", "CRC-32/ADCCP", "PKZIP" })
	    {} // end constructor
    }; // end class CRC32_PKZIP

    internal class CRC32_CASTAGNOLI : CRC32
    {
        public CRC32_CASTAGNOLI() 
            : base(CRC32Polynomials.Castagnoli, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0xE3069283, new string[] { "CRC-32C", "CRC-32/ISCSI", "CRC-32/CASTAGNOLI"})
	        {} // end constructor
    } // end class CRC32_CASTAGNOLI

}
