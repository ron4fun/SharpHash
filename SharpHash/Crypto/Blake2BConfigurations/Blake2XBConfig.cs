///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019  Mbadiwe Nnaemeka Ronald
/// Github Repository <https://github.com/ron4fun/SharpHash>
///
/// The contents of this file are subject to the
/// Mozilla Public License Version 2.0 (the "License");
/// you may not use this file except in
/// compliance with the License. You may obtain a copy of the License
/// at https://www.mozilla.org/en-US/MPL/2.0/
///
/// Software distributed under the License is distributed on an "AS IS"
/// basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
/// the License for the specific language governing rights and
/// limitations under the License.
///
/// Acknowledgements:
///
/// Thanks to Ugochukwu Mmaduekwe (https://github.com/Xor-el) for his creative
/// development of this library in Pascal/Delphi (https://github.com/Xor-el/HashLib4Pascal).
///
/// Also, I will like to thank Udezue Chukwunwike (https://github.com/IzarchTech) for
/// his contributions to the growth and development of this library.
///
////////////////////////////////////////////////////////////////////////

using SharpHash.Interfaces.IBlake2BConfigurations;

namespace SharpHash.Crypto.Blake2BConfigurations
{
    /// <summary>
    /// <b>Blake2XBConfig</b> is used to configure hash function parameters and
    /// keying.
    /// </summary>
    public sealed class Blake2XBConfig : IBlake2XBConfig
    {
        public IBlake2BConfig Blake2BConfig { get; set; } = null; // blake2B config object
        public IBlake2BTreeConfig Blake2BTreeConfig { get; set; } = null; // blake2B tree config object

        public Blake2XBConfig(IBlake2BConfig a_Blake2BConfig = null, IBlake2BTreeConfig a_Blake2BTreeConfig = null)
        {

            Blake2BConfig = a_Blake2BConfig;
            Blake2BTreeConfig = a_Blake2BTreeConfig;
        } // end cctr

        public IBlake2XBConfig Clone()
        {
            return new Blake2XBConfig(Blake2BConfig?.Clone(), Blake2BTreeConfig?.Clone());
        } // end funtion Clone

    } // end class Blake2XBConfig

}
