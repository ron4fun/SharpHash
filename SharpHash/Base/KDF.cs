using SharpHash.Interfaces;
using System;

namespace SharpHash.Base
{
    public abstract class KDF : IKDF
    {
        /// <summary>
        /// Returns the pseudo-random bytes for this object.
        /// </summary>
        /// <param name="bc">The number of pseudo-random key bytes to generate.</param>
        /// <returns>A byte array filled with pseudo-random key bytes.</returns>
        /// <exception cref="ArgumentOutOfRangeHashLibException">bc must be greater than zero.</exception>
        /// <exception cref="ArgumentHashLibException">invalid start index or end index of internal buffer.</exception>
        public abstract byte[] GetBytes(Int32 bc);

    }
}
