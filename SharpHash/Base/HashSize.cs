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

namespace SharpHash.Base
{
    // Note: The name HashSizeEnum was given considering the name conflict
    // between the enum and the Hash property for getting hash_size.
    internal enum HashSizeEnum
    {
        HashSize128 = 16,
        HashSize160 = 20,
        HashSize192 = 24,
        HashSize224 = 28,
        HashSize256 = 32,
        HashSize288 = 36,
        HashSize384 = 48,
        HashSize512 = 64
    }
}