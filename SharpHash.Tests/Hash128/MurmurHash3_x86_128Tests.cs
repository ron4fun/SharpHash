using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpHash.Base;

namespace SharpHash.Hash128.Tests
{
    [TestClass]
    public class MurmurHash3_x86_128Tests : HashWithUInt32AsKeyBaseTests
    {
        public MurmurHash3_x86_128Tests()
        {
            hash = HashFactory.Hash128.CreateMurmurHash3_x86_128();

            ExpectedHashOfEmptyData = "00000000000000000000000000000000";
            ExpectedHashOfDefaultData = "B35E1058738E067BF637B17075F14B8B";
            ExpectedHashOfRandomString = "9B5B7BA2EF3F7866889ADEAF00F3F98E";
            ExpectedHashOfZerotoFour = "35C5B3EE7B3B211600AE108800AE1088";
            ExpectedHashOfEmptyDataWithOneAsKey = "88C4ADEC54D201B954D201B954D201B9";
            ExpectedHashOfDefaultDataWithMaxUInt32AsKey = "55315FA9E8129C7390C080B8FDB1C972";
        }
    }
}