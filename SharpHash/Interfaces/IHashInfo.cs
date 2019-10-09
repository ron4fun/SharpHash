using System;

namespace SharpHash.Interfaces
{
    public interface ITransformBlock
    { }; // end class ITransformBlock

    public interface IBlockHash : IHash
    {}; // end class IBlockHash

    public interface INonBlockHash
    { }; // end class INonBlockHash

    public interface IChecksum
    { }; // end class IChecksum

    public interface ICrypto : IBlockHash
    {}; // end class ICrypto

    public interface ICryptoNotBuildIn : ICrypto
    {}; // end class ICryptoNotBuildIn

    public interface IWithKey : IHash
    {
        byte[] GetKey();
        void SetKey(byte[] value);
	    Int32? GetKeyLength();

    }; // end class IWithKey

    public interface IPBKDF2_HMAC : IKDF
    {}; // end class IPBKDF2_HMAC

    public interface IPBKDF2_HMACNotBuildIn : IPBKDF2_HMAC
    {}; // end class IPBKDF2_HMACNotBuildIn

    public interface IHMAC : IWithKey
    {}; // end class IHMAC

    public interface IIHMACNotBuildIn : IHMAC
    {}; // end class IHMACNotBuildIn

    public interface IHash16 : IHash
    {}; // end class IHash16

    public interface IHash32 : IHash
    {}; // end class IHash32

    public interface IHash64 : IHash
    {}; // end class IHash64

    public interface IHash128 : IHash
    {}; // end class IHash128

    public interface IHashWithKey : IWithKey
    {}; // end class IHashWithKey
}
