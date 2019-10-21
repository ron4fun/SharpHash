using System;
using System.IO;
using System.Text;

namespace SharpHash.Interfaces
{
    public interface IHash
    {
        string Name { get; }
        Int32 BlockSize { get; }
        Int32 HashSize { get; }
        Int32 BufferSize { get; set; }

        IHash Clone();

        IHashResult ComputeString(string a_data, Encoding encoding);

        IHashResult ComputeBytes(byte[] a_data);

        IHashResult ComputeUntyped(IntPtr a_data, Int64 a_length);

        IHashResult ComputeStream(Stream a_stream, Int64 a_length = -1);

        IHashResult ComputeFile(string a_file_name, Int64 a_from = 0, Int64 a_length = -1);

        void Initialize();

        void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length);

        void TransformBytes(byte[] a_data, Int32 a_index);

        void TransformBytes(byte[] a_data);

        void TransformUntyped(IntPtr a_data, Int64 a_length);

        IHashResult TransformFinal();

        void TransformString(string a_data, Encoding encoding);

        void TransformStream(Stream a_stream, Int64 a_length = -1);

        void TransformFile(string a_file_name, Int64 a_from = 0, Int64 a_length = -1);
    }
}