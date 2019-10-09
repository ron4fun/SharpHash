using SharpHash.Base;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;
using System.Collections.Generic;

namespace SharpHash.Hash32
{
    public class Jenkins3 : MultipleTransformNonBlock, IHash32, ITransformBlock
    {
        public Jenkins3()
          : base(4, 12)
        { } // end constructor

        override public IHash Clone()
        {
            Jenkins3 HashInstance = new Jenkins3();

            HashInstance._list = new List<byte[]>(_list);

            HashInstance.SetBufferSize(GetBufferSize());

            return HashInstance;
        } // end function Clone

        override protected IHashResult ComputeAggregatedBytes(byte[] a_data)
        {
            Int32 length, currentIndex, i1, i2, i3, i4;
            UInt32 a, b, c;

            length = a_data.Length;
            if (length == 0)
                return new HashResult((UInt32)0);

            a = 0xDEADBEEF + (UInt32)length;
            b = a;
            c = b;
            currentIndex = 0;
            while (length > 12)
            {
                i1 = a_data[currentIndex];
                currentIndex++;
                i2 = a_data[currentIndex] << 8;
                currentIndex++;
                i3 = a_data[currentIndex] << 16;
                currentIndex++;
                i4 = a_data[currentIndex] << 24;
                currentIndex++;

                a = a + (UInt32)(i1 | i2 | i3 | i4);

                i1 = a_data[currentIndex];
                currentIndex++;
                i2 = a_data[currentIndex] << 8;
                currentIndex++;
                i3 = a_data[currentIndex] << 16;
                currentIndex++;
                i4 = a_data[currentIndex] << 24;
                currentIndex++;

                b = b + (UInt32)(i1 | i2 | i3 | i4);

                i1 = a_data[currentIndex];
                currentIndex++;
                i2 = a_data[currentIndex] << 8;
                currentIndex++;
                i3 = a_data[currentIndex] << 16;
                currentIndex++;
                i4 = a_data[currentIndex] << 24;
                currentIndex++;

                c = c + (UInt32)(i1 | i2 | i3 | i4);

                a = a - c;
                a = a ^ Bits.RotateLeft32(c, 4);
                c = c + b;
                b = b - a;
                b = b ^ Bits.RotateLeft32(a, 6);
                a = a + c;
                c = c - b;
                c = c ^ Bits.RotateLeft32(b, 8);
                b = b + a;
                a = a - c;
                a = a ^ Bits.RotateLeft32(c, 16);
                c = c + b;
                b = b - a;
                b = b ^ Bits.RotateLeft32(a, 19);
                a = a + c;
                c = c - b;
                c = c ^ Bits.RotateLeft32(b, 4);
                b = b + a;

                length -= 12;
            } // end while

            switch (length)
            {
                case 12:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;
                    currentIndex++;

                    a = a + (UInt32)(i1 | i2 | i3 | i4);

                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;
                    currentIndex++;

                    b = b + (UInt32)(i1 | i2 | i3 | i4);

                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;

                    c = c + (UInt32)(i1 | i2 | i3 | i4);
                    break;

                case 11:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;
                    currentIndex++;

                    a = a + (UInt32)(i1 | i2 | i3 | i4);

                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;
                    currentIndex++;

                    b = b + (UInt32)(i1 | i2 | i3 | i4);

                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;

                    c = c + (UInt32)(i1 | i2 | i3);
                    break;

                case 10:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;
                    currentIndex++;

                    a = a + (UInt32)(i1 | i2 | i3 | i4);

                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;
                    currentIndex++;

                    b = b + (UInt32)(i1 | i2 | i3 | i4);

                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;

                    c = c + (UInt32)(i1 | i2);
                    break;

                case 9:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;
                    currentIndex++;

                    a = a + (UInt32)(i1 | i2 | i3 | i4);

                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;
                    currentIndex++;

                    b = b + (UInt32)(i1 | i2 | i3 | i4);

                    i1 = a_data[currentIndex];

                    c = c + (UInt32)i1;
                    break;

                case 8:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;
                    currentIndex++;

                    a = a + (UInt32)(i1 | i2 | i3 | i4);

                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;

                    b = b + (UInt32)(i1 | i2 | i3 | i4);
                    break;

                case 7:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;
                    currentIndex++;

                    a = a + (UInt32)(i1 | i2 | i3 | i4);

                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;

                    b = b + (UInt32)(i1 | i2 | i3);
                    break;

                case 6:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;
                    currentIndex++;

                    a = a + (UInt32)(i1 | i2 | i3 | i4);

                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;

                    b = b + (UInt32)(i1 | i2);
                    break;

                case 5:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;
                    currentIndex++;

                    a = a + (UInt32)(i1 | i2 | i3 | i4);

                    i1 = a_data[currentIndex];

                    b = b + (UInt32)i1;
                    break;

                case 4:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;
                    currentIndex++;
                    i4 = a_data[currentIndex] << 24;

                    a = a + (UInt32)(i1 | i2 | i3 | i4);
                    break;

                case 3:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;
                    currentIndex++;
                    i3 = a_data[currentIndex] << 16;

                    a = a + (UInt32)(i1 | i2 | i3);
                    break;

                case 2:
                    i1 = a_data[currentIndex];
                    currentIndex++;
                    i2 = a_data[currentIndex] << 8;

                    a = a + (UInt32)(i1 | i2);
                    break;

                case 1:
                    i1 = a_data[currentIndex];

                    a = a + (UInt32)(i1);
                    break;

            } // end switch

            c = c ^ b;
            c = c - Bits.RotateLeft32(b, 14);
            a = a ^ c;
            a = a - Bits.RotateLeft32(c, 11);
            b = b ^ a;
            b = b - Bits.RotateLeft32(a, 25);
            c = c ^ b;
            c = c - Bits.RotateLeft32(b, 16);
            a = a ^ c;
            a = a - Bits.RotateLeft32(c, 4);
            b = b ^ a;
            b = b - Bits.RotateLeft32(a, 14);
            c = c ^ b;
            c = c - Bits.RotateLeft32(b, 24);

            return new HashResult(c);
        } // end function ComputeAggregatedBytes

    } // end class Jenkins3

}
