///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019 - 2020  Mbadiwe Nnaemeka Ronald
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

using SharpHash.Interfaces.IBlake2SConfigurations;

namespace SharpHash.Crypto.Blake2SConfigurations
{
    /// <summary>
    /// <b>Blake2XSConfig</b> is used to configure hash function parameters and
    /// keying.
    /// </summary>
    public sealed class Blake2XSConfig : IBlake2XSConfig
    {
        public IBlake2SConfig Blake2SConfig { get; set; } = null; // blake2S config object
        public IBlake2STreeConfig Blake2STreeConfig { get; set; } = null; // blake2S tree config object

        public Blake2XSConfig(IBlake2SConfig a_Blake2SConfig = null, IBlake2STreeConfig a_Blake2STreeConfig = null)
        {
            Blake2SConfig = a_Blake2SConfig;
            Blake2STreeConfig = a_Blake2STreeConfig;
        } // end cctr

        public IBlake2XSConfig Clone()
        {
            return new Blake2XSConfig(Blake2SConfig?.Clone(), Blake2STreeConfig?.Clone());
        } // end funtion Clone

    } // end class Blake2XSConfig

}
