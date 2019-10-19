
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
