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

using System;

namespace SharpHash.Utils
{
    public class HashLibException : Exception
    {
        public HashLibException(string text) : base(text)
        { }  // end constructor
    }; // end class HashLibException

    public class InvalidOperationHashLibException : HashLibException
    {
        public InvalidOperationHashLibException(string text) : base(text)
        { } // end constructor
    }; // end class InvalidOperationHashLibException

    public class IndexOutOfRangeHashLibException : HashLibException
    {
        public IndexOutOfRangeHashLibException(string text) : base(text)
        { } // end constructor
    }; // end class IndexOutOfRangeHashLibException

    public class ArgumentInvalidHashLibException : HashLibException
    {
        public ArgumentInvalidHashLibException(string text) : base(text)
        { }
    }; // end class ArgumentInvalidHashLibException

    public class ArgumentHashLibException : HashLibException
    {
        public ArgumentHashLibException(string text) : base(text)
        { }
    }; // end class ArgumentHashLibException

    public class ArgumentNullHashLibException : HashLibException
    {
        public ArgumentNullHashLibException(string text) : base(text)
        { }
    }; // end class ArgumentNilHashLibException

    public class ArgumentOutOfRangeHashLibException : HashLibException
    {
        public ArgumentOutOfRangeHashLibException(string text) : base(text)
        { }
    }; // end class ArgumentOutOfRangeHashLibException

    public class NullReferenceHashLibException : HashLibException
    {
        public NullReferenceHashLibException(string text) : base(text)
        { }
    }; // end class NullReferenceHashLibException

    public class UnsupportedTypeHashLibException : HashLibException
    {
        public UnsupportedTypeHashLibException(string text) : base(text)
        { }
    }; // end class UnsupportedTypeHashLibException

    public class NotImplementedHashLibException : HashLibException
    {
        public NotImplementedHashLibException(string text) : base(text)
        { }
    }; // end class NotImplementedHashLibException
}