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

using System;

namespace SharpHash.Utils
{
    internal static class ExtendedBitConverter
    {
        public static char GetHexValue(Int32 i)
        {
            if (i < 10)
            {
                return (char)(i + '0');
            } // end if

            return (char)((i - 10) + 'A');
        } // end function GetHexValue

        public static unsafe string ToString(IntPtr value, Int32 StartIndex, Int32 Length)
        {
            Int32 chArrayLength = Length * 3;

            char[] chArray = new char[chArrayLength];

            Int32 Idx = 0;
            Int32 Index = StartIndex;
            while (Idx < chArrayLength)
            {
                byte b = ((byte*)value)[Index];
                Index += 1;

                chArray[Idx] = GetHexValue(b >> 4);
                chArray[Idx + 1] = GetHexValue(b & 15);
                chArray[Idx + 2] = '-';

                Idx += 3;
            } // end while

            return new string(chArray, 0, chArrayLength - 1);
        } // end function ToString
    } // end class ExtendedBitConverter
}