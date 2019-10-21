using System;

namespace SharpHash.Interfaces.IBlake2SConfigurations
{
    public interface IBlake2SConfig
    {
        byte[] Personalisation { get; set; }
        byte[] Salt { get; set; }
        byte[] Key { get; set; }
        Int32 HashSize { get; set; }
    } // end interface IBlake2SConfig
}