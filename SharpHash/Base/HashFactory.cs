using SharpHash.Interfaces;
using SharpHash.Checksum;
using System;
using SharpHash.KDF;
using SharpHash.Utils;
using SharpHash.Hash128;
using SharpHash.Hash64;
using SharpHash.Hash32;
using SharpHash.Crypto;

namespace SharpHash.Base
{
    public static class HashFactory
    {
        public static class NullDigestFactory
        {
            public static IHash CreateNullDigest()
            {
                return new NullDigest();
            } // end function CreateNullDigest

        } // end class NullDigestFactory

        public static class Checksum
        {
            public static IHash CreateCRC(Int32 width, UInt64 polynomial, UInt64 initialValue, 
                bool reflectIn, bool reflectOut, UInt64 outputXor, UInt64 checkValue, 
                string[] Names)
            {
                return new CRC(width, polynomial, initialValue, reflectIn,
                    reflectOut, outputXor, checkValue, Names);
            } // end function CreateCRC

            public static IHash CreateCRC(CRCStandard value)
            {
                return CRC.CreateCRCObject(value);
            } // end function CreateCRC

            public static IHash CreateCRC16(UInt64 polynomial, UInt64 initialValue,
                bool reflectIn, bool reflectOut, UInt64 outputXor, UInt64 checkValue,
                string[] Names)
            {
                return new CRC16(polynomial, initialValue, reflectIn,
                    reflectOut, outputXor, checkValue, Names);
            } // end function CreateCRC16

            /// <summary>
            /// BUYPASS, polynomial = 0x8005
            /// </summary>
            /// <returns>IHash</returns>
            public static IHash CreateCRC16_BUYPASS()
            {
                return new CRC16_BUYPASS();
            } // end function CreateCRC16_BUYPASS

            public static IHash CreateCRC32(UInt64 polynomial, UInt64 initialValue,
                bool reflectIn, bool reflectOut, UInt64 outputXor, UInt64 checkValue,
                string[] Names)
            {
                return new CRC32(polynomial, initialValue, reflectIn,
                    reflectOut, outputXor, checkValue, Names);
            } // end function CreateCRC32

            /// <summary>
            /// Castagnoli, polynomial = 0x1EDC6F41
            /// </summary>
            /// <returns>IHash</returns>
            public static IHash CreateCRC32_CASTAGNOLI()
            {
                return new CRC32_CASTAGNOLI_Fast();
            } // end function CreateCRC32_CASTAGNOLI

            /// <summary>
            /// PKZIP, polynomial = 0x04C11DB7
            /// </summary>
            /// <returns>IHash</returns>
            public static IHash CreateCRC32_PKZIP()
            {
                return new CRC32_PKZIP_Fast();
            } // end function CreateCRC32_PKZIP

            public static IHash CreateCRC64(UInt64 polynomial, UInt64 initialValue,
                bool reflectIn, bool reflectOut, UInt64 outputXor, UInt64 checkValue,
                string[] Names)
            {
                return new CRC64(polynomial, initialValue, reflectIn,
                    reflectOut, outputXor, checkValue, Names);
            } // end function CreateCRC64

            /// <summary>
            /// ECMA-182, polynomial = 0x42F0E1EBA9EA3693
            /// </summary>
            /// <returns>IHash</returns>
            public static IHash CreateCRC64_ECMA_182()
            {
                return new CRC64_ECMA_182();
            } // end function CreateCRC64_ECMA_182
            
            public static IHash CreateAdler32()
            {
                return new Adler32();
            } // end function CreateAdler32

        } // end class Checksum

        public static class Crypto
        {
            public static IHash CreateHAS160()
            {
                return new HAS160();
            } // end function CreateHAS160

            public static IHash CreatePanama()
            {
                return new Panama();
            } // end function CreatePanama


            ///////////////////////////////////////////
            /// <summary>
            /// Grindahl Hash Family
            /// </summary>
            ////////////////////////////////////////////


            public static IHash CreateGrindahl256()
            {
                return new Grindahl256();
            } // end function CreateGrindahl256

            public static IHash CreateGrindahl512()
            {
                return new Grindahl512();
            } // end function CreateGrindahl512


            ///////////////////////////////////////////
            /// <summary>
            /// RIPEMD Hash Family
            /// </summary>
            ////////////////////////////////////////////


            public static IHash CreateRIPEMD()
            {
                return new RIPEMD();
            } // end function CreateRIPEMD

            public static IHash CreateRIPEMD128()
            {
                return new RIPEMD128();
            } // end function CreateRIPEMD128

            public static IHash CreateRIPEMD160()
            {
                return new RIPEMD160();
            } // end function CreateRIPEMD160

            public static IHash CreateRIPEMD256()
            {
                return new RIPEMD256();
            } // end function CreateRIPEMD256

            public static IHash CreateRIPEMD320()
            {
                return new RIPEMD320();
            } // end function CreateRIPEMD320


            ///////////////////////////////////////////
            /// <summary>
            /// MD Hash Family
            /// </summary>
            ////////////////////////////////////////////


            public static IHash CreateMD2()
            {
                return new MD2();
            } // end function CreateMD2

            public static IHash CreateMD4()
            {
                return new MD4();
            } // end function CreateMD4

            public static IHash CreateMD5()
            {
                return new MD5();
            } // end function CreateMD5


            ///////////////////////////////////////////
            /// <summary>
            /// SHA Hash Family
            /// </summary>
            ////////////////////////////////////////////
            

            public static IHash CreateSHA0()
            {
                return new SHA0();
            } // end function CreateSHA0

            public static IHash CreateSHA1()
            {
                return new SHA1();
            } // end function CreateSHA1

            public static IHash CreateSHA2_224()
            {
                return new SHA2_224();
            } // end function CreateSHA2_224

            public static IHash CreateSHA2_256()
            {
                return new SHA2_256();
            } // end function CreateSHA2_256

            public static IHash CreateSHA2_384()
            {
                return new SHA2_384();
            } // end function CreateSHA2_384

            public static IHash CreateSHA2_512()
            {
                return new SHA2_512();
            } // end function CreateSHA2_512

            public static IHash CreateSHA2_512_224()
            {
                return new SHA2_512_224();
            } // end function CreateSHA2_512_224

            public static IHash CreateSHA2_512_256()
            {
                return new SHA2_512_256();
            } // end function CreateSHA2_512_256

            public static IHash CreateSHA3_224()
            {
                return new SHA3_224();
            } // end function CreateSHA3_224

            public static IHash CreateSHA3_256()
            {
                return new SHA3_256();
            } // end function CreateSHA3_256

            public static IHash CreateSHA3_384()
            {
                return new SHA3_384();
            } // end function CreateSHA3_384

            public static IHash CreateSHA3_512()
            {
                return new SHA3_512();
            } // end function CreateSHA3_512

            public static IHash CreateKeccak_224()
            {
                return new Keccak_224();
            } // end function CreateKeccak_224

            public static IHash CreateKeccak_256()
            {
                return new Keccak_256();
            } // end function CreateKeccak_256

            public static IHash CreateKeccak_288()
            {
                return new Keccak_288();
            } // end function CreateKeccak_288

            public static IHash CreateKeccak_384()
            {
                return new Keccak_384();
            } // end function CreateKeccak_384

            public static IHash CreateKeccak_512()
            {
                return new Keccak_512();
            } // end function CreateKeccak_512

        } // end class Crypto

        public static class Hash32
        {
            public static IHash CreateAP()
            {
                return new AP();
            } // end function CreateAP

            public static IHash CreateBernstein()
            {
                return new Bernstein();
            } // end function CreateBernstein

            public static IHash CreateBernstein1()
            {
                return new Bernstein1();
            } // end function CreateBernstein1

            public static IHash CreateBKDR()
            {
                return new BKDR();
            } // end function CreateBKDR

            public static IHash CreateDEK()
            {
                return new DEK();
            } // end function CreateDEK

            public static IHash CreateDJB()
            {
                return new DJB();
            } // end function CreateDJB

            public static IHash CreateELF()
            {
                return new ELF();
            } // end function CreateELF

            public static IHash CreateFNV()
            {
                return new FNV();
            } // end function CreateFNV

            public static IHash CreateFNV1a()
            {
                return new FNV1a();
            } // end function CreateFNV1a

            public static IHash CreateJenkins3(Int32 initialValue = 0)
            {
                return new Jenkins3(initialValue);
            } // end function CreateJenkins3

            public static IHash CreateJS()
            {
                return new JS();
            } // end function CreateJS

            public static IHashWithKey CreateMurmur2()
            {
                return new Murmur2();
            } // end function CreateMurmur2

            public static IHashWithKey CreateMurmurHash3_x86_32()
            {
                return new MurmurHash3_x86_32();
            } // end function CreateMurmurHash3_x86_32

            public static IHash CreateOneAtTime()
            {
                return new OneAtTime();
            } // end function CreateOneAtTime

            public static IHash CreatePJW()
            {
                return new PJW();
            } // end function CreatePJW

            public static IHash CreateRotating()
            {
                return new Rotating();
            } // end function CreateRotating

            public static IHash CreateRS()
            {
                return new RS();
            } // end function CreateRS

            public static IHash CreateSDBM()
            {
                return new SDBM();
            } // end function CreateSDBM

            public static IHash CreateShiftAndXor()
            {
                return new ShiftAndXor();
            } // end function CreateShiftAndXor

            public static IHash CreateSuperFast()
            {
                return new SuperFast();
            } // end function CreateSuperFast

            public static IHashWithKey CreateXXHash32()
            {
                return new XXHash32();
            } // end function CreateXXHash32

        } // end class Hash32

        public static class Hash64
        {
            public static IHash CreateFNV()
            {
                return new FNV64();
            } // end function CreateFNV

            public static IHash CreateFNV1a()
            {
                return new FNV1a64();
            } // end function CreateFNV1a

            public static IHashWithKey CreateMurmur2()
            {
                return new Murmur2_64();
            } // end function CreateMurmur2

            public static IHashWithKey CreateSipHash2_4()
            {
                return new SipHash2_4();
            } // end function CreateSipHash2_4

            public static IHashWithKey CreateXXHash64()
            {
                return new XXHash64();
            } // end function CreateXXHash64

        } // end class Hash64

        public static class Hash128
        {
            public static IHashWithKey CreateMurmurHash3_x86_128()
            {
                return new MurmurHash3_x86_128();
            } // end function CreateMurmurHash3_x86_128

            public static IHashWithKey CreateMurmurHash3_x64_128()
            {
                return new MurmurHash3_x64_128();
            } // end function CreateMurmurHash3_x64_128

        } // end class Hash128

        public static class XOF
        {
            public static IHash CreateShake_128(UInt64 a_XofSizeInBits)
            {
                IXOF Xof = (new Shake_128() as IXOF);
                Xof.XOFSizeInBits = a_XofSizeInBits;

                return Xof as IHash;
            } // end function CreateShake_128

            public static IHash CreateShake_256(UInt64 a_XofSizeInBits)
            {
                IXOF Xof = (new Shake_256() as IXOF);
                Xof.XOFSizeInBits = a_XofSizeInBits;

                return Xof as IHash;
            } // end function CreateShake_256

            public static IHash CreateCShake_128(byte[] AN, byte[] AS, UInt64 a_XofSizeInBits)
            {
                IXOF Xof = (new CShake_128(AN, AS) as IXOF);
                Xof.XOFSizeInBits = a_XofSizeInBits;

                return Xof as IHash;
            } // end function CreateCShake_128

            public static IHash CreateCShake_256(byte[] AN, byte[] AS, UInt64 a_XofSizeInBits)
            {
                IXOF Xof = (new CShake_256(AN, AS) as IXOF);
                Xof.XOFSizeInBits = a_XofSizeInBits;

                return Xof as IHash;
            } // end function CreateCShake_256

            public static IHash CreateKMAC128XOF(byte[] a_KMACKey, byte[] a_Customization, 
                UInt64 a_XofSizeInBits)
            {
                return KMAC128XOF.CreateKMAC128XOF(a_KMACKey, a_Customization, a_XofSizeInBits);
            } // end function CreateKMAC128XOF

            public static IHash CreateKMAC256XOF(byte[] a_KMACKey, byte[] a_Customization,
                UInt64 a_XofSizeInBits)
            {
                return KMAC256XOF.CreateKMAC256XOF(a_KMACKey, a_Customization, a_XofSizeInBits);
            } // end function CreateKMAC256XOF

        } // end class XOF

        public static class KMAC
        {
            public static IHash CreateKMAC128(byte[] a_KMACKey, byte[] a_Customization,
                UInt64 a_OutputLengthInBits)
            {
                return KMAC128.CreateKMAC128(a_KMACKey, a_Customization, a_OutputLengthInBits);
            } // end function CreateKMAC128

            public static IHash CreateKMAC256(byte[] a_KMACKey, byte[] a_Customization,
                UInt64 a_OutputLengthInBits)
            {
                return KMAC256.CreateKMAC256(a_KMACKey, a_Customization, a_OutputLengthInBits);
            } // end function CreateKMAC256

        } // end class KMAC

        public static class HMAC
        {
            public static IHMAC CreateHMAC(IHash hash)
            {
                return new HMACNotBuildInAdapter(hash);
            } // end function CreateHMAC

        } // end class HMAC
        
        public static class PBKDF2_HMAC
        {
            /// <summary>
            /// Initializes a new interface instance of the TPBKDF2_HMAC class using a password, a salt, a number of iterations and an Instance of an "IHash" to be used as an "IHMAC" hashing implementation to derive the key.
            /// </summary>
            /// <param name="a_hash">The name of the "IHash" implementation to be transformed to an "IHMAC" Instance so it can be used to derive the key.</param>
            /// <param name="a_password">The password to derive the key for.</param>
            /// <param name="a_salt">The salt to use to derive the key.</param>
            /// <param name="a_iterations">The number of iterations to use to derive the key.</param>
            /// <exception cref="ArgumentNilHashLibException">The password, salt or algorithm is Nil.</exception>
            /// <exception cref="ArgumentHashLibException">The iteration is less than 1.</exception>
            public static IPBKDF2_HMAC CreatePBKDF2_HMAC(IHash a_hash, byte[] a_password, 
                byte[] a_salt, UInt32 a_iterations)
            {
                if (a_hash == null)
                    throw new ArgumentNilHashLibException(PBKDF2_HMACNotBuildInAdapter.UninitializedInstance);

                if (a_password == null || a_password.Length == 0)
                    throw new ArgumentNilHashLibException(PBKDF2_HMACNotBuildInAdapter.EmptyPassword);

                if (a_salt == null || a_salt.Length == 0)
                    throw new ArgumentNilHashLibException(PBKDF2_HMACNotBuildInAdapter.EmptySalt);

                if (a_iterations < 1)
                    throw new ArgumentHashLibException(PBKDF2_HMACNotBuildInAdapter.IterationtooSmall);

                return new PBKDF2_HMACNotBuildInAdapter(a_hash, a_password, a_salt, a_iterations);
            } // end function CreatePBKDF2_HMAC

        } // end class PBKDF2_HMAC

    } // end class HashFactory

}
