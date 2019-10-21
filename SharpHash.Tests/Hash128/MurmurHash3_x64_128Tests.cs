using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash128.Tests
{
    [TestClass]
    public class MurmurHash3_x64_128Tests : HashWithUInt32AsKeyBaseTests
    {
        public MurmurHash3_x64_128Tests()
        {
            hash = HashFactory.Hash128.CreateMurmurHash3_x64_128();

            ExpectedHashOfEmptyData = "00000000000000000000000000000000";
            ExpectedHashOfDefaultData = "705BD3C954B94BE056F06B68662E6364";
            ExpectedHashOfRandomString = "D30654ABBD8227E367D73523F0079673";
            ExpectedHashOfZerotoFour = "0F04E459497F3FC1ECCC6223A28DD613";
            ExpectedHashOfEmptyDataWithOneAsKey = "4610ABE56EFF5CB551622DAA78F83583";
            ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "ADFD14988FB1F8582A1B67C1BBACC218";
        }
    }
}