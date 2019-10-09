using System;

namespace SharpHash.Utils
{
    public class HashLibException : Exception
    {        
	    public HashLibException(string text) : base(text)
        {}  // end constructor

    }; // end class HashLibException

    public class InvalidOperationHashLibException : HashLibException
    {
	    public InvalidOperationHashLibException(string text) : base(text)
        {} // end constructor

    }; // end class InvalidOperationHashLibException

    public class IndexOutOfRangeHashLibException : HashLibException
    {
	    public IndexOutOfRangeHashLibException(string text) : base(text)
        {} // end constructor

    }; // end class IndexOutOfRangeHashLibException

    public class ArgumentInvalidHashLibException : HashLibException
    {
        public ArgumentInvalidHashLibException(string text) : base(text)
        {}
    }; // end class ArgumentInvalidHashLibException

    public class ArgumentHashLibException : HashLibException
    {
        public ArgumentHashLibException(string text) : base(text)
        { }
    }; // end class ArgumentHashLibException

    public class ArgumentNilHashLibException : HashLibException
    {
        public ArgumentNilHashLibException(string text) : base(text)
        {}
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
