using SharpHash.Base;
using SharpHash.Interfaces;
using System;

namespace SharpHash.Checksum
{
    public abstract class CRC32Fast : Hash, IChecksum, IBlockHash, IHash16, ITransformBlock
    {
        protected UInt32 CurrentCRC = 0;

        public CRC32Fast()
            : base(4, 1)
        { } // end constructor

        override public void Initialize()
        {
            CurrentCRC = 0;
        } // end function Initialize

        override public IHashResult TransformFinal()
        {
            IHashResult res = new HashResult(CurrentCRC);
            Initialize();

            return res;
        } // end function TransformFinal

        protected void LocalCRCCompute(UInt32[] a_CRCTable, byte[] a_data, Int32 a_index,
            Int32 a_length)
        {
            UInt32 LCRC, LA, LB, LC, LD;
            UInt32[] LCRCTable;

            LCRC = ~ CurrentCRC; // LCRC := System.High(UInt32) xor FCurrentCRC;
            LCRCTable = a_CRCTable;
            while (a_length >= 16)
            {
                LA = LCRCTable[(3 * 256) + a_data[a_index + 12]] ^ LCRCTable
                    [(2 * 256) + a_data[a_index + 13]] ^ LCRCTable
                    [(1 * 256) + a_data[a_index + 14]] ^ LCRCTable
                    [(0 * 256) + a_data[a_index + 15]];

                LB = LCRCTable[(7 * 256) + a_data[a_index + 8]] ^ LCRCTable
                    [(6 * 256) + a_data[a_index + 9]] ^ LCRCTable
                    [(5 * 256) + a_data[a_index + 10]] ^ LCRCTable
                    [(4 * 256) + a_data[a_index + 11]];

                LC = LCRCTable[(11 * 256) + a_data[a_index + 4]] ^ LCRCTable
                    [(10 * 256) + a_data[a_index + 5]] ^ LCRCTable
                    [(9 * 256) + a_data[a_index + 6]] ^ LCRCTable
                    [(8 * 256) + a_data[a_index + 7]];

                LD = LCRCTable[(15 * 256) + ((LCRC & 0xFF) ^ a_data[a_index])] ^ LCRCTable
                    [(14 * 256) + (((LCRC >> 8) & 0xFF) ^ a_data[a_index + 1])] ^ LCRCTable
                    [(13 * 256) + (((LCRC >> 16) & 0xFF) ^ a_data[a_index + 2])] ^ LCRCTable
                    [(12 * 256) + ((LCRC >> 24) ^ a_data[a_index + 3])];

                LCRC = LD ^ LC ^ LB ^ LA;

                a_index += 16;
                a_length -= 16;
            } // end while

            a_length--;
            while (a_length >= 0)
            {
                LCRC = LCRCTable[(byte)(LCRC ^ a_data[a_index])] ^ (LCRC >> 8);
                a_index++;
                a_length--;
            } // end while

            CurrentCRC = ~ LCRC; // FCurrentCRC := LCRC xor System.High(UInt32);
        } // end function LocalCRCCompute

        static public UInt32[] Init_CRC_Table(UInt32 a_polynomial)
        {
            Int32 LIdx, LJIdx, LKIdx;
            UInt32 LRes;

            UInt32[] res = new UInt32[16 * 256];

            for (LIdx = 0; LIdx < 256; LIdx++)
            {
                LRes = (UInt32)LIdx;
                for (LJIdx = 0; LJIdx < 16; LJIdx++)
                {
                    LKIdx = 0;
                    while (LKIdx < 8)
                    {
                        // faster branchless variant
                        LRes = (UInt32)((LRes >> 1) ^ (-(Int32)(LRes & 1) & a_polynomial));
                        res[(LJIdx * 256) + LIdx] = LRes;
                        LKIdx++;
                    } // end while
                } // end for
            } // end for

            return res;
        } // end function Init_CRC_Table
                
    } // end class CRC32Fast

    public class CRC32_PKZIP_Fast : CRC32Fast
    {
        public CRC32_PKZIP_Fast()
        {
            CRC32_PKZIP_Table = Init_CRC_Table(CRC32_PKZIP_Polynomial);
        } // end constructor

        // Polynomial Reversed
        static private UInt32 CRC32_PKZIP_Polynomial = 0xEDB88320;

        private UInt32[] CRC32_PKZIP_Table = null;

        override public IHash Clone()
        {
            CRC32_PKZIP_Fast HashInstance = new CRC32_PKZIP_Fast();
            HashInstance.CurrentCRC = CurrentCRC;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            LocalCRCCompute(CRC32_PKZIP_Table, a_data, a_index, a_length);
        } // end function TransformBytes

    } // end class CRC32_PKZIP

    public class CRC32_CASTAGNOLI_Fast : CRC32Fast
    {
        // Polynomial Reversed
        static private UInt32 CRC32_CASTAGNOLI_Polynomial = 0x82F63B78;

        private UInt32[] CRC32_CASTAGNOLI_Table = null;

        public CRC32_CASTAGNOLI_Fast()
        {
            CRC32_CASTAGNOLI_Table = Init_CRC_Table(CRC32_CASTAGNOLI_Polynomial);
        } // end constructor

        override public IHash Clone()
        {
            CRC32_CASTAGNOLI_Fast HashInstance = new CRC32_CASTAGNOLI_Fast();
            HashInstance.CurrentCRC = CurrentCRC;

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            LocalCRCCompute(CRC32_CASTAGNOLI_Table, a_data, a_index, a_length);
        } // end function TransformBytes

    } // end class CRC32_CASTAGNOLI

}
