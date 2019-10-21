using System;

namespace SharpHash.Interfaces
{
    public interface ICRC : IHash
    {
        string[] Names { get; }
        Int32 Width { get; }
        UInt64 Polynomial { get; }
        UInt64 Initial { get; }
        bool IsInputReflected { get; }
        bool IsOutputReflected { get; }
        UInt64 OutputXor { get; }
        UInt64 CheckValue { get; }
    }
}