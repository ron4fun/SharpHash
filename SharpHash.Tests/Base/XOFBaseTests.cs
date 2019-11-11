using SharpHash.Interfaces;
using SharpHash.Tests;
using System;

namespace SharpHash
{
    public class XOFBaseTests
    {
        protected static unsafe void CallShouldRaiseException(IXOF XofInstance)
        {
            byte[] Output = new byte[XofInstance.XOFSizeInBits >> 3];

            fixed (byte* bPtr = TestConstants.Bytesabcde)
            {
                IntPtr abcdePtr = (IntPtr)bPtr;

                XofInstance.Initialize();
                XofInstance.TransformUntyped(abcdePtr, TestConstants.Bytesabcde.Length);
                XofInstance.DoOutput(ref Output, 0, (UInt64)Output.Length);
                // this call below should raise exception since we have already read from the Xof
                XofInstance.TransformUntyped(abcdePtr, TestConstants.Bytesabcde.Length);
            } //
        } //
    }
}