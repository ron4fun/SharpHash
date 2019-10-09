using System;

namespace SharpHash.Interfaces
{
    public interface ICRC : IHash
    {
        string[] GetNames();
        Int32 GetWidth();
        UInt64 GetPolynomial();
        UInt64 GetInit();
        bool GetReflectIn();
        bool GetReflectOut();
        UInt64 GetXOROut();
        UInt64 GetCheckValue();
    }
}
