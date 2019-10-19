
using SharpHash.Interfaces;
using SharpHash.Utils;

namespace SharpHash.XOFandKMAC.Tests
{
    public abstract class CShakeTests
    {
        protected readonly byte[] FS;

        public CShakeTests()
        {
            FS = Converters.ConvertStringToBytes("Email Signature");
        } //

    }
}
