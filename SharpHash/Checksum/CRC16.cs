using SharpHash.Base;
using SharpHash.Interfaces;
using System;

namespace SharpHash.Checksum
{
    public abstract class CRC16Polynomials
    {
	    static public UInt16 BUYPASS = 0x8005;
    }; // end class CRC16Polynomials


    public class CRC16 : Hash, IChecksum, IBlockHash, IHash16, ITransformBlock
    {
        private ICRC CRCAlgorithm = null;

        public CRC16(UInt64 _poly, UInt64 _Init, bool _refIn, bool _refOut, 
            UInt64 _XorOut, UInt64 _check, string[] _Names)
		: base(2, 1)
        {
            CRCAlgorithm = new CRC(16, _poly, _Init, _refIn, _refOut, _XorOut, _check, _Names);
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

    } // end class CRC16

    public class CRC16_BUYPASS : CRC16
    {
        public CRC16_BUYPASS() 
            : base(CRC16Polynomials.BUYPASS, 0x0000, false, false, 0x0000, 0xFEE8, new string[] { "CRC-16/BUYPASS", "CRC-16/VERIFONE" })
	    {} // end constructor
    } // end class CRC16_BUYPASS

}
