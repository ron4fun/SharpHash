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