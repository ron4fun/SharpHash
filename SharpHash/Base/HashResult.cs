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

using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.Base
{
    public sealed class HashResult : IHashResult
    {
        private byte[] hash = null;

        private static readonly string ImpossibleRepresentationInt32 = "Current Data Structure cannot be Represented as an 'Int32' Type.";
        private static readonly string ImpossibleRepresentationUInt8 = "Current Data Structure cannot be Represented as an 'UInt8' Type.";
        private static readonly string ImpossibleRepresentationUInt16 = "Current Data Structure cannot be Represented as an 'UInt16' Type.";
        private static readonly string ImpossibleRepresentationUInt32 = "Current Data Structure cannot be Represented as an 'UInt32' Type.";
        private static readonly string ImpossibleRepresentationUInt64 = "Current Data Structure cannot be Represented as an 'UInt64' Type.";

        public HashResult()
        {
            hash = new byte[0];
        } // end constructor

        public HashResult(UInt64 a_hash)
        {
            hash = new byte[8];

            hash[0] = (byte)(a_hash >> 56);
            hash[1] = (byte)(a_hash >> 48);
            hash[2] = (byte)(a_hash >> 40);
            hash[3] = (byte)(a_hash >> 32);
            hash[4] = (byte)(a_hash >> 24);
            hash[5] = (byte)(a_hash >> 16);
            hash[6] = (byte)(a_hash >> 8);
            hash[7] = (byte)(a_hash);
        } // end constructor

        public HashResult(byte[] a_hash)
        {
            hash = a_hash.DeepCopy();
        } // end constructor

        public HashResult(UInt32 a_hash)
        {
            hash = new byte[4];

            hash[0] = (byte)(a_hash >> 24);
            hash[1] = (byte)(a_hash >> 16);
            hash[2] = (byte)(a_hash >> 8);
            hash[3] = (byte)(a_hash);
        } // end constructor

        public HashResult(byte a_hash)
        {
            hash = new byte[1];
            hash[0] = a_hash;
        } // end constructor

        public HashResult(UInt16 a_hash)
        {
            hash = new byte[2];

            hash[0] = (byte)(a_hash >> 8);
            hash[1] = (byte)(a_hash);
        } // end constructor

        public HashResult(Int32 a_hash)
        {
            hash = new byte[4];

            hash[0] = (byte)(Utils.Bits.Asr32(a_hash, 24));
            hash[1] = (byte)(Utils.Bits.Asr32(a_hash, 16));
            hash[2] = (byte)(Utils.Bits.Asr32(a_hash, 8));
            hash[3] = (byte)(a_hash);
        } // end constructor

        // Copy Constructor
        public HashResult(HashResult right)
        {
            hash = right.hash.DeepCopy();
        }

        public bool CompareTo(IHashResult a_hashResult)
        {
            return SlowEquals(a_hashResult.GetBytes(), hash);
        } // end function CompareTo

        public byte[] GetBytes()
        {
            return hash.DeepCopy();
        } // end function GetBytes

        public override Int32 GetHashCode()
        {
            string Temp = Convert.ToBase64String(hash);

            UInt32 LResult = 0;
            Int32 I = 0, Top = Temp.Length;

            while (I < Top)
            {
                LResult = Bits.RotateLeft32((UInt32)LResult, 5);
                LResult = ((UInt32)LResult ^ (UInt32)Temp[I]);
                I += 1;
            } // end while

            return (Int32)LResult;
        } // end function GetHashCode

        public Int32 GetInt32()
        {
            if (hash.Length != 4)
                throw new InvalidOperationHashLibException(ImpossibleRepresentationInt32);
           
            return (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];
        } // end function GetInt32

        public byte GetUInt8()
        {
            if (hash.Length != 1)
                throw new InvalidOperationHashLibException(ImpossibleRepresentationUInt8);
           
            return hash[0];
        } // end function GetUInt8

        public UInt16 GetUInt16()
        {
            if (hash.Length != 2)
                throw new InvalidOperationHashLibException(ImpossibleRepresentationUInt16);
          
            return (UInt16)((hash[0] << 8) | hash[1]);
        } // end function GetUInt16

        public UInt32 GetUInt32()
        {
            if (hash.Length != 4)
                throw new InvalidOperationHashLibException(ImpossibleRepresentationUInt32);
          
            return (UInt32)((hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3]);
        } // end function GetUInt32

        public UInt64 GetUInt64()
        {
            if (hash.Length != 8)
                throw new InvalidOperationHashLibException(ImpossibleRepresentationUInt64);
            
            return ((UInt64)(hash[0]) << 56) | ((UInt64)(hash[1]) << 48) | ((UInt64)(hash[2]) << 40) | ((UInt64)(hash[3]) << 32) |
                ((UInt64)(hash[4]) << 24) | ((UInt64)(hash[5]) << 16) | ((UInt64)(hash[6]) << 8) | (UInt64)(hash[7]);
        } // end function GetUInt64

        private static bool SlowEquals(byte[] a_ar1, byte[] a_ar2)
        {
            UInt32 diff = (UInt32)(a_ar1?.Length ^ a_ar2?.Length), I = 0;

            while (I <= (a_ar1?.Length - 1) && I <= (a_ar2?.Length - 1))
            {
                diff = diff | (UInt32)(a_ar1[I] ^ a_ar2[I]);
                I += 1;
            } // end while

            return diff == 0;
        } // end function SlowEquals

        public string ToString(bool a_group = false)
        {
            return Converters.ConvertBytesToHexString(hash, a_group);
        } // end function ToString
    }
}