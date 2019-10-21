using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Checksum
{
    /// <summary>
    /// Enum of all defined and implemented CRC standards.
    /// </summary>
    public enum CRCStandard
    {
        /// <summary>
        /// CRC standard named "CRC3_GSM".
        /// </summary>
        CRC3_GSM = 0,

        /// <summary>
        /// CRC standard named "CRC3_ROHC".
        /// </summary>
        CRC3_ROHC,

        /// <summary>
        /// CRC standard named "CRC4_INTERLAKEN".
        /// </summary>
        CRC4_INTERLAKEN,

        /// <summary>
        /// CRC standard named "CRC4_ITU".
        /// </summary>
        CRC4_ITU,

        /// <summary>
        /// CRC standard named "CRC5_EPC".
        /// </summary>
        CRC5_EPC,

        /// <summary>
        /// CRC standard named "CRC5_ITU".
        /// </summary>
        CRC5_ITU,

        /// <summary>
        /// CRC standard named "CRC5_USB".
        /// </summary>
        CRC5_USB,

        /// <summary>
        /// CRC standard named "CRC6_CDMA2000A".
        /// </summary>
        CRC6_CDMA2000A,

        /// <summary>
        /// CRC standard named "CRC6_CDMA2000B".
        /// </summary>
        CRC6_CDMA2000B,

        /// <summary>
        /// CRC standard named "CRC6_DARC".
        /// </summary>
        CRC6_DARC,

        /// <summary>
        /// CRC standard named "CRC6_GSM".
        /// </summary>
        CRC6_GSM,

        /// <summary>
        /// CRC standard named "CRC6_ITU".
        /// </summary>
        CRC6_ITU,

        /// <summary>
        /// CRC standard named "CRC7".
        /// </summary>
        CRC7,

        /// <summary>
        /// CRC standard named "CRC7_ROHC".
        /// </summary>
        CRC7_ROHC,

        /// <summary>
        /// CRC standard named "CRC7_UMTS".
        /// </summary>
        CRC7_UMTS,

        /// <summary>
        /// CRC standard named "CRC8".
        /// </summary>
        CRC8,

        /// <summary>
        /// CRC standard named "CRC8_AUTOSAR".
        /// </summary>
        CRC8_AUTOSAR,

        /// <summary>
        /// CRC standard named "CRC8_BLUETOOTH".
        /// </summary>
        CRC8_BLUETOOTH,

        /// <summary>
        /// CRC standard named "CRC8_CDMA2000".
        /// </summary>
        CRC8_CDMA2000,

        /// <summary>
        /// CRC standard named "CRC8_DARC".
        /// </summary>
        CRC8_DARC,

        /// <summary>
        /// CRC standard named "CRC8_DVBS2".
        /// </summary>
        CRC8_DVBS2,

        /// <summary>
        /// CRC standard named "CRC8_EBU".
        /// </summary>
        CRC8_EBU,

        /// <summary>
        /// CRC standard named "CRC8_GSMA".
        /// </summary>
        CRC8_GSMA,

        /// <summary>
        /// CRC standard named "CRC8_GSMB".
        /// </summary>
        CRC8_GSMB,

        /// <summary>
        /// CRC standard named "CRC8_ICODE".
        /// </summary>
        CRC8_ICODE,

        /// <summary>
        /// CRC standard named "CRC8_ITU".
        /// </summary>
        CRC8_ITU,

        /// <summary>
        /// CRC standard named "CRC8_LTE".
        /// </summary>
        CRC8_LTE,

        /// <summary>
        /// CRC standard named "CRC8_MAXIM".
        /// </summary>
        CRC8_MAXIM,

        /// <summary>
        /// CRC standard named "CRC8_OPENSAFETY".
        /// </summary>
        CRC8_OPENSAFETY,

        /// <summary>
        /// CRC standard named "CRC8_ROHC".
        /// </summary>
        CRC8_ROHC,

        /// <summary>
        /// CRC standard named "CRC8_SAEJ1850".
        /// </summary>
        CRC8_SAEJ1850,

        /// <summary>
        /// CRC standard named "CRC8_WCDMA".
        /// </summary>
        CRC8_WCDMA,

        /// <summary>
        /// CRC standard named "CRC10".
        /// </summary>
        CRC10,

        /// <summary>
        /// CRC standard named "CRC10_CDMA2000".
        /// </summary>
        CRC10_CDMA2000,

        /// <summary>
        /// CRC standard named "CRC10_GSM".
        /// </summary>
        CRC10_GSM,

        /// <summary>
        /// CRC standard named "CRC11".
        /// </summary>
        CRC11,

        /// <summary>
        /// CRC standard named "CRC11_UMTS".
        /// </summary>
        CRC11_UMTS,

        /// <summary>
        /// CRC standard named "CRC12_CDMA2000".
        /// </summary>
        CRC12_CDMA2000,

        /// <summary>
        /// CRC standard named "CRC12_DECT".
        /// </summary>
        CRC12_DECT,

        /// <summary>
        /// CRC standard named "CRC12_GSM".
        /// </summary>
        CRC12_GSM,

        /// <summary>
        /// CRC standard named "CRC12_UMTS".
        /// </summary>
        CRC12_UMTS,

        /// <summary>
        /// CRC standard named "CRC13_BBC".
        /// </summary>
        CRC13_BBC,

        /// <summary>
        /// CRC standard named "CRC14_DARC".
        /// </summary>
        CRC14_DARC,

        /// <summary>
        /// CRC standard named "CRC14_GSM".
        /// </summary>
        CRC14_GSM,

        /// <summary>
        /// CRC standard named "CRC15".
        /// </summary>
        CRC15,

        /// <summary>
        /// CRC standard named "CRC15_MPT1327".
        /// </summary>
        CRC15_MPT1327,

        /// <summary>
        /// CRC standard named "ARC".
        /// </summary>
        ARC,

        /// <summary>
        /// CRC standard named "CRC16_AUGCCITT".
        /// </summary>
        CRC16_AUGCCITT,

        /// <summary>
        /// CRC standard named "CRC16_BUYPASS".
        /// </summary>
        CRC16_BUYPASS,

        /// <summary>
        /// CRC standard named "CRC16_CCITTFALSE".
        /// </summary>
        CRC16_CCITTFALSE,

        /// <summary>
        /// CRC standard named "CRC16_CDMA2000".
        /// </summary>
        CRC16_CDMA2000,

        /// <summary>
        /// CRC standard named "CRC16_CMS".
        /// </summary>
        CRC16_CMS,

        /// <summary>
        /// CRC standard named "CRC16_DDS110".
        /// </summary>
        CRC16_DDS110,

        /// <summary>
        /// CRC standard named "CRC16_DECTR".
        /// </summary>
        CRC16_DECTR,

        /// <summary>
        /// CRC standard named "CRC16_DECTX".
        /// </summary>
        CRC16_DECTX,

        /// <summary>
        /// CRC standard named "CRC16_DNP".
        /// </summary>
        CRC16_DNP,

        /// <summary>
        /// CRC standard named "CRC16_EN13757".
        /// </summary>
        CRC16_EN13757,

        /// <summary>
        /// CRC standard named "CRC16_GENIBUS".
        /// </summary>
        CRC16_GENIBUS,

        /// <summary>
        /// CRC standard named "CRC16_GSM".
        /// </summary>
        CRC16_GSM,

        /// <summary>
        /// CRC standard named "CRC16_LJ1200".
        /// </summary>
        CRC16_LJ1200,

        /// <summary>
        /// CRC standard named "CRC16_MAXIM".
        /// </summary>
        CRC16_MAXIM,

        /// <summary>
        /// CRC standard named "CRC16_MCRF4XX".
        /// </summary>
        CRC16_MCRF4XX,

        /// <summary>
        /// CRC standard named "CRC16_OPENSAFETYA".
        /// </summary>
        CRC16_OPENSAFETYA,

        /// <summary>
        /// CRC standard named "CRC16_OPENSAFETYB".
        /// </summary>
        CRC16_OPENSAFETYB,

        /// <summary>
        /// CRC standard named "CRC16_PROFIBUS".
        /// </summary>
        CRC16_PROFIBUS,

        /// <summary>
        /// CRC standard named "CRC16_RIELLO".
        /// </summary>
        CRC16_RIELLO,

        /// <summary>
        /// CRC standard named "CRC16_T10DIF".
        /// </summary>
        CRC16_T10DIF,

        /// <summary>
        /// CRC standard named "CRC16_TELEDISK".
        /// </summary>
        CRC16_TELEDISK,

        /// <summary>
        /// CRC standard named "CRC16_TMS37157".
        /// </summary>
        CRC16_TMS37157,

        /// <summary>
        /// CRC standard named "CRC16_USB".
        /// </summary>
        CRC16_USB,

        /// <summary>
        /// CRC standard named "CRCA".
        /// </summary>
        CRCA,

        /// <summary>
        /// CRC standard named "KERMIT".
        /// </summary>
        KERMIT,

        /// <summary>
        /// CRC standard named "MODBUS".
        /// </summary>
        MODBUS,

        /// <summary>
        /// CRC standard named "X25".
        /// </summary>
        X25,

        /// <summary>
        /// CRC standard named "XMODEM".
        /// </summary>
        XMODEM,

        /// <summary>
        /// CRC standard named "CRC17_CANFD".
        /// </summary>
        CRC17_CANFD,

        /// <summary>
        /// CRC standard named "CRC21_CANFD".
        /// </summary>
        CRC21_CANFD,

        /// <summary>
        /// CRC standard named "CRC24".
        /// </summary>
        CRC24,

        /// <summary>
        /// CRC standard named "CRC24_BLE".
        /// </summary>
        CRC24_BLE,

        /// <summary>
        /// CRC standard named "CRC24_FLEXRAYA".
        /// </summary>
        CRC24_FLEXRAYA,

        /// <summary>
        /// CRC standard named "CRC24_FLEXRAYB".
        /// </summary>
        CRC24_FLEXRAYB,

        /// <summary>
        /// CRC standard named "CRC24_INTERLAKEN".
        /// </summary>
        CRC24_INTERLAKEN,

        /// <summary>
        /// CRC standard named "CRC24_LTEA".
        /// </summary>
        CRC24_LTEA,

        /// <summary>
        /// CRC standard named "CRC24_LTEB".
        /// </summary>
        CRC24_LTEB,

        /// <summary>
        /// CRC standard named "CRC30_CDMA".
        /// </summary>
        CRC30_CDMA,

        /// <summary>
        /// CRC standard named "CRC31_PHILIPS".
        /// </summary>
        CRC31_PHILIPS,

        /// <summary>
        /// CRC standard named "CRC32".
        /// </summary>
        CRC32,

        /// <summary>
        /// CRC standard named "CRC32_AUTOSAR".
        /// </summary>
        CRC32_AUTOSAR,

        /// <summary>
        /// CRC standard named "CRC32_BZIP2".
        /// </summary>
        CRC32_BZIP2,

        /// <summary>
        /// CRC standard named "CRC32C".
        /// </summary>
        CRC32C,

        /// <summary>
        /// CRC standard named "CRC32D".
        /// </summary>
        CRC32D,

        /// <summary>
        /// CRC standard named "CRC32_MPEG2".
        /// </summary>
        CRC32_MPEG2,

        /// <summary>
        /// CRC standard named "CRC32_POSIX".
        /// </summary>
        CRC32_POSIX,

        /// <summary>
        /// CRC standard named "CRC32Q".
        /// </summary>
        CRC32Q,

        /// <summary>
        /// CRC standard named "JAMCRC".
        /// </summary>
        JAMCRC,

        /// <summary>
        /// CRC standard named "XFER".
        /// </summary>
        XFER,

        /// <summary>
        /// CRC standard named "CRC40_GSM".
        /// </summary>
        CRC40_GSM,

        /// <summary>
        /// CRC standard named "CRC64".
        /// </summary>
        CRC64,

        /// <summary>
        /// CRC standard named "CRC64_GOISO".
        /// </summary>
        CRC64_GOISO,

        /// <summary>
        /// CRC standard named "CRC64_WE".
        /// </summary>
        CRC64_WE,

        /// <summary>
        /// CRC standard named "CRC64_XZ".
        /// </summary>
        CRC64_XZ
    }; // end enum

    internal sealed class CRC : Hash, IChecksum, ICRC, ITransformBlock
    {
        private string[] names = null;
        private Int32 width;
        private UInt64 polynomial, init, xorOut, checkValue, CRCMask, CRCHighBitMask, hash;
        private bool reflectIn, reflectOut, IsTableGenerated;

        private UInt64[] CRCTable;

        private static Int32 Delta = 7;

        public CRC(Int32 _Width, UInt64 _poly, UInt64 _Init,
            bool _refIn, bool _refOut, UInt64 _XorOut, UInt64 _check, string[] _Names)
            : base(0, 0) // Ok, Nothing serious..
        {
            IsTableGenerated = false;

            if (_Width >= 0 && _Width <= 7)
            {
                hash_size = 1;
                block_size = 1;
            } // end if
            else if (_Width >= 8 && _Width <= 16)
            {
                hash_size = 2;
                block_size = 1;
            } // end else if
            else if (_Width >= 17 && _Width <= 39)
            {
                hash_size = 4;
                block_size = 1;
            } // end else if
            else
            {
                hash_size = 8;
                block_size = 1;
            } // end else

            names = new string[_Names.Length];
            for (Int32 i = 0; i < _Names.Length; i++)
                names[i] = _Names[i];

            width = _Width;
            polynomial = _poly;
            init = _Init;
            reflectIn = _refIn;
            reflectOut = _refOut;
            xorOut = _XorOut;
            checkValue = _check;
        } // end constructor

<<<<<<< Updated upstream
        public override IHash Clone()
    	{
=======
        override public IHash Clone()
        {
>>>>>>> Stashed changes
            CRC HashInstance = new CRC(width, polynomial, init, reflectIn, reflectOut, xorOut, checkValue, names);
            HashInstance.CRCMask = CRCMask;
            HashInstance.CRCHighBitMask = CRCHighBitMask;
            HashInstance.hash = hash;
            HashInstance.IsTableGenerated = IsTableGenerated;

            if (!(CRCTable == null || CRCTable.Length == 0))
            {
                HashInstance.CRCTable = new UInt64[CRCTable.Length];
                for (Int32 i = 0; i < CRCTable.Length; i++)
                    HashInstance.CRCTable[i] = CRCTable[i];
            } // end if

            HashInstance.BufferSize = BufferSize;

            return HashInstance;
        } // end function Clone

<<<<<<< Updated upstream
        public override string Name => Names[0];
=======
        override public string Name
        {
            get
            {
                return Names[0];
            }
        }
>>>>>>> Stashed changes

        public override void Initialize()
        {
            // initialize some bitmasks
            CRCMask = ((((UInt64)1 << (Width - 1)) - 1) << 1) | 1;
            CRCHighBitMask = (UInt64)1 << (Width - 1);
            hash = init;

            if (Width > Delta) // then use table
            {
                if (!IsTableGenerated)
                    GenerateTable();

                if (reflectIn)
                    hash = Reflect(hash, Width);
            } // end if
        } // end function Initialize

        public override IHashResult TransformFinal()
        {
            UInt64 LUInt64;
            UInt32 LUInt32;
            UInt16 LUInt16;
            byte LUInt8;

            if (Width > Delta)
            {
                if (reflectIn ^ reflectOut)
                    hash = Reflect(hash, Width);
            } // end if
            else
            {
                if (reflectOut)
                    hash = Reflect(hash, Width);
            } // end else

            hash = hash ^ xorOut;
            hash = hash & CRCMask;

            if (width == 21) // special case
            {
                LUInt32 = (UInt32)hash;

                IHashResult result = new HashResult(LUInt32);

                Initialize();

                return result;
            } // end if

            Int64 value = Width >> 3;

            if (value == 0)
            {
                LUInt8 = (byte)hash;
                Initialize();
                return new HashResult(LUInt8);
            } // end result
            
            if (value == 1 || value == 2)
            {
                LUInt16 = (UInt16)hash;
                Initialize();
                return new HashResult(LUInt16);
            } // end result
            
            if (value == 3 || value == 4)
            {
                LUInt32 = (UInt32)hash;
                Initialize();
                return new HashResult(LUInt32);
            } // end result

            LUInt64 = hash;
            Initialize();
            return new HashResult(LUInt64);
        } // end function TransformFinal

        public override void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            // table driven CRC reportedly only works for 8, 16, 24, 32 bits
            // HOWEVER, it seems to work for everything > 7 bits, so use it
            // accordingly

            Int32 i = a_index;

            unsafe
            {
                fixed (byte* ptr_a_data = a_data)
                {
                    if (Width > Delta)
                        CalculateCRCbyTable((IntPtr)ptr_a_data, a_length, i);
                    else
                        CalculateCRCdirect((IntPtr)ptr_a_data, a_length, i);
                }
            }
        } // end function TransformBytes

        static public ICRC CreateCRCObject(CRCStandard a_value)
        {
            switch (a_value)
            {
                case CRCStandard.CRC3_GSM:
                    return new CRC(3, 0x3, 0x0, false, false, 0x7, 0x4, new string[] { "CRC-3/GSM" });

                case CRCStandard.CRC3_ROHC:
                    return new CRC(3, 0x3, 0x7, true, true, 0x0, 0x6, new string[] { "CRC-3/ROHC" });

                case CRCStandard.CRC4_INTERLAKEN:
                    return new CRC(4, 0x3, 0xF, false, false, 0xF, 0xB, new string[] { "CRC-4/INTERLAKEN" });

                case CRCStandard.CRC4_ITU:
                    return new CRC(4, 0x3, 0x0, true, true, 0x0, 0x7, new string[] { "CRC-4/ITU" });

                case CRCStandard.CRC5_EPC:
                    return new CRC(5, 0x9, 0x9, false, false, 0x00, 0x00, new string[] { "CRC-5/EPC" });

                case CRCStandard.CRC5_ITU:
                    return new CRC(5, 0x15, 0x00, true, true, 0x00, 0x07, new string[] { "CRC-5/ITU" });

                case CRCStandard.CRC5_USB:
                    return new CRC(5, 0x05, 0x1F, true, true, 0x1F, 0x19, new string[] { "CRC-5/USB" });

                case CRCStandard.CRC6_CDMA2000A:
                    return new CRC(6, 0x27, 0x3F, false, false, 0x00, 0x0D, new string[] { "CRC-6/CDMA2000-A" });

                case CRCStandard.CRC6_CDMA2000B:
                    return new CRC(6, 0x07, 0x3F, false, false, 0x00, 0x3B, new string[] { "CRC-6/CDMA2000-B" });

                case CRCStandard.CRC6_DARC:
                    return new CRC(6, 0x19, 0x00, true, true, 0x00, 0x26, new string[] { "CRC-6/DARC" });

                case CRCStandard.CRC6_GSM:
                    return new CRC(6, 0x2F, 0x00, false, false, 0x3F, 0x13, new string[] { "CRC-6/GSM" });

                case CRCStandard.CRC6_ITU:
                    return new CRC(6, 0x03, 0x00, true, true, 0x00, 0x06, new string[] { "CRC-6/ITU" });

                case CRCStandard.CRC7:
                    return new CRC(7, 0x09, 0x00, false, false, 0x00, 0x75, new string[] { "CRC-7" });

                case CRCStandard.CRC7_ROHC:
                    return new CRC(7, 0x4F, 0x7F, true, true, 0x00, 0x53, new string[] { "CRC-7/ROHC" });

                case CRCStandard.CRC7_UMTS:
                    return new CRC(7, 0x45, 0x00, false, false, 0x00, 0x61, new string[] { "CRC-7/UMTS" });

                case CRCStandard.CRC8:
                    return new CRC(8, 0x07, 0x00, false, false, 0x00, 0xF4, new string[] { "CRC-8" });

                case CRCStandard.CRC8_AUTOSAR:
                    return new CRC(8, 0x2F, 0xFF, false, false, 0xFF, 0xDF, new string[] { "CRC-8/AUTOSAR" });

                case CRCStandard.CRC8_BLUETOOTH:
                    return new CRC(8, 0xA7, 0x00, true, true, 0x00, 0x26, new string[] { "CRC-8/BLUETOOTH" });

                case CRCStandard.CRC8_CDMA2000:
                    return new CRC(8, 0x9B, 0xFF, false, false, 0x00, 0xDA, new string[] { "CRC-8/CDMA2000" });

                case CRCStandard.CRC8_DARC:
                    return new CRC(8, 0x39, 0x00, true, true, 0x00, 0x15, new string[] { "CRC-8/DARC" });

                case CRCStandard.CRC8_DVBS2:
                    return new CRC(8, 0xD5, 0x00, false, false, 0x00, 0xBC, new string[] { "CRC-8/DVB-S2" });

                case CRCStandard.CRC8_EBU:
                    return new CRC(8, 0x1D, 0xFF, true, true, 0x00, 0x97, new string[] { "CRC-8/EBU", "CRC-8/AES" });

                case CRCStandard.CRC8_GSMA:
                    return new CRC(8, 0x1D, 0x00, false, false, 0x00, 0x37, new string[] { "CRC-8/GSM-A" });

                case CRCStandard.CRC8_GSMB:
                    return new CRC(8, 0x49, 0x00, false, false, 0xFF, 0x94, new string[] { "CRC-8/GSM-B" });

                case CRCStandard.CRC8_ICODE:
                    return new CRC(8, 0x1D, 0xFD, false, false, 0x00, 0x7E, new string[] { "CRC-8/I-CODE" });

                case CRCStandard.CRC8_ITU:
                    return new CRC(8, 0x07, 0x00, false, false, 0x55, 0xA1, new string[] { "CRC-8/ITU" });

                case CRCStandard.CRC8_LTE:
                    return new CRC(8, 0x9B, 0x00, false, false, 0x00, 0xEA, new string[] { "CRC-8/LTE" });

                case CRCStandard.CRC8_MAXIM:
                    return new CRC(8, 0x31, 0x00, true, true, 0x00, 0xA1, new string[] { "CRC-8/MAXIM", "DOW-CRC" });

                case CRCStandard.CRC8_OPENSAFETY:
                    return new CRC(8, 0x2F, 0x00, false, false, 0x00, 0x3E, new string[] { "CRC-8/OPENSAFETY" });

                case CRCStandard.CRC8_ROHC:
                    return new CRC(8, 0x07, 0xFF, true, true, 0x00, 0xD0, new string[] { "CRC-8/ROHC" });

                case CRCStandard.CRC8_SAEJ1850:
                    return new CRC(8, 0x1D, 0xFF, false, false, 0xFF, 0x4B, new string[] { "CRC-8/SAE-J1850" });

                case CRCStandard.CRC8_WCDMA:
                    return new CRC(8, 0x9B, 0x00, true, true, 0x00, 0x25, new string[] { "CRC-8/WCDMA" });

                case CRCStandard.CRC10:
                    return new CRC(10, 0x233, 0x000, false, false, 0x000, 0x199, new string[] { "CRC-10" });

                case CRCStandard.CRC10_CDMA2000:
                    return new CRC(10, 0x3D9, 0x3FF, false, false, 0x000, 0x233, new string[] { "CRC-10/CDMA2000" });

                case CRCStandard.CRC10_GSM:
                    return new CRC(10, 0x175, 0x000, false, false, 0x3FF, 0x12A, new string[] { "CRC-10/GSM" });

                case CRCStandard.CRC11:
                    return new CRC(11, 0x385, 0x01A, false, false, 0x000, 0x5A3, new string[] { "CRC-11" });

                case CRCStandard.CRC11_UMTS:
                    return new CRC(11, 0x307, 0x000, false, false, 0x000, 0x061, new string[] { "CRC-11/UMTS" });

                case CRCStandard.CRC12_CDMA2000:
                    return new CRC(12, 0xF13, 0xFFF, false, false, 0x000, 0xD4D, new string[] { "CRC-12/CDMA2000" });

                case CRCStandard.CRC12_DECT:
                    return new CRC(12, 0x80F, 0x000, false, false, 0x000, 0xF5B, new string[] { "CRC-12/DECT", "X-CRC-12" });

                case CRCStandard.CRC12_GSM:
                    return new CRC(12, 0xD31, 0x000, false, false, 0xFFF, 0xB34, new string[] { "CRC-12/GSM" });

                case CRCStandard.CRC12_UMTS:
                    return new CRC(12, 0x80F, 0x000, false, true, 0x000, 0xDAF, new string[] { "CRC-12/UMTS", "CRC-12/3GPP" });

                case CRCStandard.CRC13_BBC:
                    return new CRC(13, 0x1CF5, 0x0000, false, false, 0x0000, 0x04FA, new string[] { "CRC-13/BBC" });

                case CRCStandard.CRC14_DARC:
                    return new CRC(14, 0x0805, 0x0000, true, true, 0x0000, 0x082D, new string[] { "CRC-14/DARC" });

                case CRCStandard.CRC14_GSM:
                    return new CRC(14, 0x202D, 0x0000, false, false, 0x3FFF, 0x30AE, new string[] { "CRC-14/GSM" });

                case CRCStandard.CRC15:
                    return new CRC(15, 0x4599, 0x0000, false, false, 0x0000, 0x059E, new string[] { "CRC-15" });

                case CRCStandard.CRC15_MPT1327:
                    return new CRC(15, 0x6815, 0x0000, false, false, 0x0001, 0x2566, new string[] { "CRC-15/MPT1327" });

                case CRCStandard.ARC:
                    return new CRC(16, 0x8005, 0x0000, true, true, 0x0000, 0xBB3D, new string[] { "CRC-16", "ARC", "CRC-IBM", "CRC-16/ARC", "CRC-16/LHA" });

                case CRCStandard.CRC16_AUGCCITT:
                    return new CRC(16, 0x1021, 0x1D0F, false, false, 0x0000, 0xE5CC, new string[] { "CRC-16/AUG-CCITT", "CRC-16/SPI-FUJITSU" });

                case CRCStandard.CRC16_BUYPASS:
                    return new CRC(16, 0x8005, 0x0000, false, false, 0x0000, 0xFEE8, new string[] { "CRC-16/BUYPASS", "CRC-16/VERIFONE" });

                case CRCStandard.CRC16_CCITTFALSE:
                    return new CRC(16, 0x1021, 0xFFFF, false, false, 0x0000, 0x29B1, new string[] { "CRC-16/CCITT-FALSE" });

                case CRCStandard.CRC16_CDMA2000:
                    return new CRC(16, 0xC867, 0xFFFF, false, false, 0x0000, 0x4C06, new string[] { "CRC-16/CDMA2000" });

                case CRCStandard.CRC16_CMS:
                    return new CRC(16, 0x8005, 0xFFFF, false, false, 0x0000, 0xAEE7, new string[] { "CRC-16/CMS" });

                case CRCStandard.CRC16_DDS110:
                    return new CRC(16, 0x8005, 0x800D, false, false, 0x0000, 0x9ECF, new string[] { "CRC-16/DDS-110" });

                case CRCStandard.CRC16_DECTR:
                    return new CRC(16, 0x0589, 0x0000, false, false, 0x0001, 0x007E, new string[] { "CRC-16/DECT-R", "R-CRC-16" });

                case CRCStandard.CRC16_DECTX:
                    return new CRC(16, 0x0589, 0x0000, false, false, 0x0000, 0x007F, new string[] { "CRC-16/DECT-X", "X-CRC-16" });

                case CRCStandard.CRC16_DNP:
                    return new CRC(16, 0x3D65, 0x0000, true, true, 0xFFFF, 0xEA82, new string[] { "CRC-16/DNP" });

                case CRCStandard.CRC16_EN13757:
                    return new CRC(16, 0x3D65, 0x0000, false, false, 0xFFFF, 0xC2B7, new string[] { "CRC-16/EN13757" });

                case CRCStandard.CRC16_GENIBUS:
                    return new CRC(16, 0x1021, 0xFFFF, false, false, 0xFFFF, 0xD64E, new string[] { "CRC-16/GENIBUS", "CRC-16/EPC", "CRC-16/I-CODE", "CRC-16/DARC" });

                case CRCStandard.CRC16_GSM:
                    return new CRC(16, 0x1021, 0x0000, false, false, 0xFFFF, 0xCE3C, new string[] { "CRC-16/GSM" });

                case CRCStandard.CRC16_LJ1200:
                    return new CRC(16, 0x6F63, 0x0000, false, false, 0x0000, 0xBDF4, new string[] { "CRC-16/LJ1200" });

                case CRCStandard.CRC16_MAXIM:
                    return new CRC(16, 0x8005, 0x0000, true, true, 0xFFFF, 0x44C2, new string[] { "CRC-16/MAXIM" });

                case CRCStandard.CRC16_MCRF4XX:
                    return new CRC(16, 0x1021, 0xFFFF, true, true, 0x0000, 0x6F91, new string[] { "CRC-16/MCRF4XX" });

                case CRCStandard.CRC16_OPENSAFETYA:
                    return new CRC(16, 0x5935, 0x0000, false, false, 0x0000, 0x5D38, new string[] { "CRC-16/OPENSAFETY-A" });

                case CRCStandard.CRC16_OPENSAFETYB:
                    return new CRC(16, 0x755B, 0x0000, false, false, 0x0000, 0x20FE, new string[] { "CRC-16/OPENSAFETY-B" });

                case CRCStandard.CRC16_PROFIBUS:
                    return new CRC(16, 0x1DCF, 0xFFFF, false, false, 0xFFFF, 0xA819, new string[] { "CRC-16/PROFIBUS", "CRC-16/IEC-61158-2" });

                case CRCStandard.CRC16_RIELLO:
                    return new CRC(16, 0x1021, 0xB2AA, true, true, 0x0000, 0x63D0, new string[] { "CRC-16/RIELLO" });

                case CRCStandard.CRC16_T10DIF:
                    return new CRC(16, 0x8BB7, 0x0000, false, false, 0x0000, 0xD0DB, new string[] { "CRC-16/T10-DIF" });

                case CRCStandard.CRC16_TELEDISK:
                    return new CRC(16, 0xA097, 0x0000, false, false, 0x0000, 0x0FB3, new string[] { "CRC-16/TELEDISK" });

                case CRCStandard.CRC16_TMS37157:
                    return new CRC(16, 0x1021, 0x89EC, true, true, 0x0000, 0x26B1, new string[] { "CRC-16/TMS37157" });

                case CRCStandard.CRC16_USB:
                    return new CRC(16, 0x8005, 0xFFFF, true, true, 0xFFFF, 0xB4C8, new string[] { "CRC-16/USB" });

                case CRCStandard.CRCA:
                    return new CRC(16, 0x1021, 0xC6C6, true, true, 0x0000, 0xBF05, new string[] { "CRC-A" });

                case CRCStandard.KERMIT:
                    return new CRC(16, 0x1021, 0x0000, true, true, 0x0000, 0x2189, new string[] { "KERMIT", "CRC-16/CCITT", "CRC-16/CCITT-TRUE", "CRC-CCITT" });

                case CRCStandard.MODBUS:
                    return new CRC(16, 0x8005, 0xFFFF, true, true, 0x0000, 0x4B37, new string[] { "MODBUS" });

                case CRCStandard.X25:
                    return new CRC(16, 0x1021, 0xFFFF, true, true, 0xFFFF, 0x906E, new string[] { "X-25", "CRC-16/IBM-SDLC", "CRC-16/ISO-HDLC", "CRC-B" });

                case CRCStandard.XMODEM:
                    return new CRC(16, 0x1021, 0x0000, false, false, 0x0000, 0x31C3, new string[] { "XMODEM", "ZMODEM", "CRC-16/ACORN" });

                case CRCStandard.CRC17_CANFD:
                    return new CRC(17, 0x1685B, 0x00000, false, false, 0x00000, 0x04F03, new string[] { "CRC-17/CAN-FD" });

                case CRCStandard.CRC21_CANFD:
                    return new CRC(21, 0x102899, 0x00000, false, false, 0x00000, 0x0ED841, new string[] { "CRC-21/CAN-FD" });

                case CRCStandard.CRC24:
                    return new CRC(24, 0x864CFB, 0xB704CE, false, false, 0x000000, 0x21CF02, new string[] { "CRC-24", "CRC-24/OPENPGP" });

                case CRCStandard.CRC24_BLE:
                    return new CRC(24, 0x00065B, 0x555555, true, true, 0x000000, 0xC25A56, new string[] { "CRC-24/BLE" });

                case CRCStandard.CRC24_FLEXRAYA:
                    return new CRC(24, 0x5D6DCB, 0xFEDCBA, false, false, 0x000000, 0x7979BD, new string[] { "CRC-24/FLEXRAY-A" });

                case CRCStandard.CRC24_FLEXRAYB:
                    return new CRC(24, 0x5D6DCB, 0xABCDEF, false, false, 0x000000, 0x1F23B8, new string[] { "CRC-24/FLEXRAY-B" });

                case CRCStandard.CRC24_INTERLAKEN:
                    return new CRC(24, 0x328B63, 0xFFFFFF, false, false, 0xFFFFFF, 0xB4F3E6, new string[] { "CRC-24/INTERLAKEN" });

                case CRCStandard.CRC24_LTEA:
                    return new CRC(24, 0x864CFB, 0x000000, false, false, 0x000000, 0xCDE703, new string[] { "CRC-24/LTE-A" });

                case CRCStandard.CRC24_LTEB:
                    return new CRC(24, 0x800063, 0x000000, false, false, 0x000000, 0x23EF52, new string[] { "CRC-24/LTE-B" });

                case CRCStandard.CRC30_CDMA:
                    return new CRC(30, 0x2030B9C7, 0x3FFFFFFF, false, false, 0x3FFFFFFF, 0x04C34ABF, new string[] { "CRC-30/CDMA" });

                case CRCStandard.CRC31_PHILIPS:
                    return new CRC(31, 0x04C11DB7, 0x7FFFFFFF, false, false, 0x7FFFFFFF, 0x0CE9E46C, new string[] { "CRC-31/PHILLIPS" });

                case CRCStandard.CRC32:
                    return new CRC(32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0xCBF43926, new string[] { "CRC-32", "CRC-32/ADCCP", "PKZIP" });

                case CRCStandard.CRC32_AUTOSAR:
                    return new CRC(32, 0xF4ACFB13, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0x1697D06A, new string[] { "CRC-32/AUTOSAR" });

                case CRCStandard.CRC32_BZIP2:
                    return new CRC(32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0xFFFFFFFF, 0xFC891918, new string[] { "CRC-32/BZIP2", "CRC-32/AAL5", "CRC-32/DECT-B", "B-CRC-32" });

                case CRCStandard.CRC32C:
                    return new CRC(32, 0x1EDC6F41, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0xE3069283, new string[] { "CRC-32C", "CRC-32/ISCSI", "CRC-32/CASTAGNOLI", "CRC-32/INTERLAKEN" });

                case CRCStandard.CRC32D:
                    return new CRC(32, 0xA833982B, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0x87315576, new string[] { "CRC-32D" });

                case CRCStandard.CRC32_MPEG2:
                    return new CRC(32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0x00000000, 0x0376E6E7, new string[] { "CRC-32/MPEG-2" });

                case CRCStandard.CRC32_POSIX:
                    return new CRC(32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0x00000000, 0x0376E6E7, new string[] { "CRC-32/POSIX", "CKSUM" });

                case CRCStandard.CRC32Q:
                    return new CRC(32, 0x814141AB, 0x00000000, false, false, 0x00000000, 0x3010BF7F, new string[] { "CRC-32Q" });

                case CRCStandard.JAMCRC:
                    return new CRC(32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0x00000000, 0x340BC6D9, new string[] { "JAMCRC" });

                case CRCStandard.XFER:
                    return new CRC(32, 0x000000AF, 0x00000000, false, false, 0x00000000, 0xBD0BE338, new string[] { "XFER" });

                case CRCStandard.CRC40_GSM:
                    return new CRC(40, 0x0004820009, 0x0000000000, false, false, 0xFFFFFFFFFF, 0xD4164FC646, new string[] { "CRC-40/GSM" });

                case CRCStandard.CRC64:
                    return new CRC(64, 0x42F0E1EBA9EA3693, 0x0000000000000000, false, false, 0x0000000000000000, 0x6C40DF5F0B497347, new string[] { "CRC-64", "CRC-64/ECMA-182" });

                case CRCStandard.CRC64_GOISO:
                    return new CRC(64, 0x000000000000001B, 0xFFFFFFFFFFFFFFFF, true, true, 0xFFFFFFFFFFFFFFFF, 0xB90956C775A41001, new string[] { "CRC-64/GO-ISO" });

                case CRCStandard.CRC64_WE:
                    return new CRC(64, 0x42F0E1EBA9EA3693, (UInt64)(0xFFFFFFFFFFFFFFFF), false, false, (UInt64)(0xFFFFFFFFFFFFFFFF), 0x62EC59E3F1A4F00A, new string[] { "CRC-64/WE" });

                case CRCStandard.CRC64_XZ:
                    return new CRC(64, 0x42F0E1EBA9EA3693, (UInt64)(0xFFFFFFFFFFFFFFFF), true, true, (UInt64)(0xFFFFFFFFFFFFFFFF), (UInt64)(0x995DC9BBDF1939FA), new string[] { "CRC-64/XZ", "CRC-64/GO-ECMA" });
            } // end switch

            throw new ArgumentHashLibException("Invalid CRCStandard object.");
        } // end function CreateCRCObject

<<<<<<< Updated upstream
        public string[] Names => names;

        public Int32 Width => width;

        public UInt64 Polynomial => polynomial;

        public UInt64 Initial => init;

        public bool IsInputReflected => reflectIn;

        public bool IsOutputReflected => reflectOut;

        public UInt64 OutputXor => xorOut;

        public UInt64 CheckValue => checkValue;
              
=======
        public string[] Names
        {
            get
            {
                return names;
            }
        } // end property Names

        public Int32 Width
        {
            get
            {
                return width;
            }
        } // end property Width

        public UInt64 Polynomial
        {
            get
            {
                return polynomial;
            }
        } // end property Polynomial

        public UInt64 Initial
        {
            get
            {
                return init;
            }
        } // end property Initial

        public bool IsInputReflected
        {
            get
            {
                return reflectIn;
            }
        } // end property IsInputReflected

        public bool IsOutputReflected
        {
            get
            {
                return reflectOut;
            }
        } // end property IsOutputReflected

        public UInt64 OutputXor
        {
            get
            {
                return xorOut;
            }
        } // end property OutputXor

        public UInt64 CheckValue
        {
            get
            {
                return checkValue;
            }
        } // end property CheckValue

>>>>>>> Stashed changes
        private void GenerateTable()
        {
            UInt64 bit, crc;
            UInt32 i = 0, j = 0;

            CRCTable = new UInt64[256];

            unsafe
            {
                fixed (UInt64* ptr_Fm_CRCTable = &CRCTable[0])
                {
                    while (i < 256)
                    {
                        crc = i;
                        if (reflectIn)
                            crc = Reflect(crc, 8);

                        crc = crc << (width - 8);
                        j = 0;
                        while (j < 8)
                        {
                            bit = crc & CRCHighBitMask;
                            crc = crc << 1;
                            if (bit != 0)
                                crc = (crc ^ polynomial);
                            j++;
                        } // end while

                        if (reflectIn)
                            crc = Reflect(crc, width);

                        crc = crc & CRCMask;
                        ptr_Fm_CRCTable[i] = crc;
                        i++;
                    } // end while
                }
            }

            IsTableGenerated = true;
        } // end function GenerateTable

        // tables work only for 8, 16, 24, 32 bit CRC
        private void CalculateCRCbyTable(IntPtr a_data, Int32 a_data_length, Int32 a_index)
        {
            Int32 Length, i;
            UInt64 tmp;

            Length = a_data_length;
            i = a_index;
            tmp = hash;

            unsafe
            {
                fixed (UInt64* ptr_Fm_CRCTable = &CRCTable[0])
                {
                    if (reflectIn)
                    {
                        while (Length > 0)
                        {
                            tmp = (tmp >> 8) ^ ptr_Fm_CRCTable[(byte)(tmp ^ ((byte*)a_data)[i])];
                            i++;
                            Length--;
                        } // end while
                    } // end if
                    else
                    {
                        while (Length > 0)
                        {
                            tmp = (tmp << 8) ^ ptr_Fm_CRCTable
                            [(byte)((tmp >> (width - 8)) ^ ((byte*)a_data)[i])];
                            i++;
                            Length--;
                        } // end while
                    } // end else
                }
            }

            hash = tmp;
        } // end function CalculateCRCbyTable

        // fast bit by bit algorithm without augmented zero bytes.
        // does not use lookup table, suited for polynomial orders between 1...32.
        private void CalculateCRCdirect(IntPtr a_data, Int32 a_data_length, Int32 a_index)
        {
            Int32 Length, i;
            UInt64 c, bit, j;

            Length = a_data_length;
            i = a_index;

            while (Length > 0)
            {
                unsafe
                {
                    c = ((byte*)a_data)[i];
                }

                if (reflectIn)
                    c = Reflect(c, 8);

                j = 0x80;
                while (j > 0)
                {
                    bit = hash & CRCHighBitMask;
                    hash = hash << 1;
                    if ((c & j) > 0)
                        bit = bit ^ CRCHighBitMask;
                    if (bit > 0)
                        hash = hash ^ polynomial;
                    j = j >> 1;
                } // end while

                i++;
                Length--;
            } // end while
        } // end function CalculateCRCdirect

        // reflects the lower 'width' bits of 'value'
        private static UInt64 Reflect(UInt64 a_value, Int32 a_width)
        {
            UInt64 j, i, result = 0;

            j = 1;
            i = (UInt64)1 << (a_width - 1);
            while (i != 0)
            {
                if ((a_value & i) != 0)
                    result = result | j;

                j = j << 1;
                i = i >> 1;
            } // end while

            return result;
        } // end function Reflect
    } // end class CRC
}