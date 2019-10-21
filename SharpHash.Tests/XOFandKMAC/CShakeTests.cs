using SharpHash.Utils;
using System.Text;

namespace SharpHash.XOFandKMAC.Tests
{
    public abstract class CShakeTests
    {
        protected readonly byte[] FS;

        public CShakeTests()
        {
            FS = Converters.ConvertStringToBytes("Email Signature", Encoding.UTF8);
        } //
    }
}