using System;

namespace SharpHash.Interfaces.IBlake2SConfigurations
{
    public interface IBlake2STreeConfig
    {
        byte FanOut { get; set; }
        byte MaxDepth { get; set; }
        byte NodeDepth { get; set; }
        byte InnerHashSize { get; set; }
        UInt32 LeafSize { get; set; }
        UInt64 NodeOffset { get; set; }
        bool IsLastNode { get; set; }
    } // end interface IBlake2STreeConfig
}