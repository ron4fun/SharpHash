using System;

namespace SharpHash.Interfaces.IBlake2BConfigurations
{
    public interface IBlake2BConfig
    {
        byte[] Personalisation { get; set; }
        byte[] Salt { get; set; }
        byte[] Key { get; set; }
        Int32 HashSize { get; set; }
    } // end interface IBlake2BConfig
}