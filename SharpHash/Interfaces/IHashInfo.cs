using SharpHash.KDF;
using System;

namespace SharpHash.Interfaces
{
    public interface ITransformBlock
    { }; // end interface ITransformBlock

    public interface IBlockHash : IHash
    { }; // end interface IBlockHash

    public interface INonBlockHash
    { }; // end interface INonBlockHash

    public interface IChecksum
    { }; // end interface IChecksum

    public interface ICrypto : IBlockHash
    { }; // end interface ICrypto

    public interface ICryptoNotBuildIn : ICrypto
    { }; // end interface ICryptoNotBuildIn

    public interface IWithKey : IHash
    {
        byte[] Key { get; set; }
        Int32? KeyLength { get; }
    }; // end interface IWithKey

    public interface IMAC : IHash
    {
        void Clear();

        byte[] Key { get; set; }
    }; // end interface IMAC

    public interface IHMAC : IMAC
    { }; // end interface IHMAC

    public interface IIHMACNotBuildIn : IHMAC
    { }; // end interface IHMACNotBuildIn

    public interface IKMAC : IMAC
    { }; // end interface IKMAC

    public interface IKMACNotBuildIn : IKMAC
    { }; // end interface IKMACNotBuildIn

    public interface IHash16 : IHash
    { }; // end interface IHash16

    public interface IHash32 : IHash
    { }; // end interface IHash32

    public interface IHash64 : IHash
    { }; // end interface IHash64

    public interface IHash128 : IHash
    { }; // end interface IHash128

    public interface IHashWithKey : IWithKey
    { }; // end interface IHashWithKey

    public interface IPBKDF2_HMAC : IKDF
    { }; // end interface IPBKDF2_HMAC

    public interface IPBKDF2_HMACNotBuildIn : IPBKDF2_HMAC
    { }; // end interface IPBKDF2_HMACNotBuildIn

    public interface IPBKDF_Argon2 : IKDF
    { }; // end interface IPBKDF_Argon2

    public interface IPBKDF_Argon2NotBuildIn : IPBKDF_Argon2
    { }; // end interface IPBKDF_Argon2NotBuildIn

    public interface IPBKDF_Scrypt : IKDF
    { }; // end interface IPBKDF_Scrypt

    public interface IPBKDF_ScryptNotBuildIn : IPBKDF_Scrypt
    { }; // end interface IPBKDF_ScryptNotBuildIn

    public interface IXOF : IHash
    {
        UInt64 XOFSizeInBits { get; set; }

        void DoOutput(ref byte[] destination, UInt64 destinationOffset, UInt64 outputLength);
    } // end interface IXOF

    public interface IArgon2Parameters
    {
        void Clear();

        byte[] Salt { get; }
        byte[] Secret { get; }
        byte[] Additional { get; }
        Int32 Iterations { get; }
        Int32 Memory { get; }
        Int32 Lanes { get; }
        Argon2Type Type { get; }
        Argon2Version Version { get; }
    }  // end interface IArgon2Parameters

    public interface IArgon2ParametersBuilder
    {
        IArgon2ParametersBuilder WithParallelism(Int32 a_parallelism);

        IArgon2ParametersBuilder WithSalt(byte[] a_salt);

        IArgon2ParametersBuilder WithSecret(byte[] a_secret);

        IArgon2ParametersBuilder WithAdditional(byte[] a_additional);

        IArgon2ParametersBuilder WithIterations(Int32 a_iterations);

        IArgon2ParametersBuilder WithMemoryAsKB(Int32 a_memory);

        IArgon2ParametersBuilder WithMemoryPowOfTwo(Int32 a_memory);

        IArgon2ParametersBuilder WithVersion(Argon2Version a_version);

        void Clear();

        IArgon2Parameters Build();
    } // end interface IArgon2ParametersBuilder
}