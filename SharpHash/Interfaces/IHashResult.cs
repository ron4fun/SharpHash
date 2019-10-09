using System;

namespace SharpHash.Interfaces
{
    public interface IHashResult
    {
        byte[] GetBytes();
        byte GetUInt8();
        UInt16 GetUInt16();
        UInt32 GetUInt32();
        Int32 GetInt32();
        UInt64 GetUInt64();
        string ToString(bool a_group = false);
        Int32 GetHashCode();
        bool CompareTo(IHashResult a_hashResult);
    }
}
