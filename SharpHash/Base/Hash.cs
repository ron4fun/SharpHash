using SharpHash.Interfaces;
using SharpHash.Utils;
using System;
using System.IO;
using System.Text;

namespace SharpHash.Base
{
    internal abstract class Hash : IHash
    {
        private Int32 buffer_size;
        protected Int32 block_size;
        protected Int32 hash_size;

        public virtual string Name => GetType().Name;

<<<<<<< Updated upstream
        public virtual Int32 BufferSize 
=======
        virtual public Int32 BufferSize
>>>>>>> Stashed changes
        {
            get => buffer_size;
            set
            {
                if (value > 0)
                {
                    buffer_size = value;
                } // end if
                else
                {
                    throw new ArgumentHashLibException(InvalidBufferSize);
                } // end else
            }
        } // end property BufferSize

        public virtual Int32 BlockSize => block_size;

        public virtual Int32 HashSize => hash_size;

        protected static Int32 BUFFER_SIZE = (Int32)(64 * 1024); // 64Kb

        private static string IndexOutOfRange = "Current Index Is Out Of Range";
        private static string InvalidBufferSize = "\"BufferSize\" Must Be Greater Than Zero";
        private static string UnAssignedStream = "Input Stream Is Unassigned";
        private static string FileNotExist = "Specified File Not Found";
        private static string CloneNotYetImplemented = "Clone Not Yet Implemented For \"{0}\"";

        public Hash(Int32 a_hash_size, Int32 a_block_size)
        {
            block_size = a_block_size;
            hash_size = a_hash_size;
            buffer_size = BUFFER_SIZE;
        } // end constructor

        public abstract void Initialize();

<<<<<<< Updated upstream
        public virtual IHash Clone()
	    {
		    throw new NotImplementedHashLibException(String.Format(CloneNotYetImplemented, Name));
	    } // end function Clone

	    public virtual IHashResult ComputeString(string a_data, Encoding encoding)
=======
        virtual public IHash Clone()
        {
            throw new NotImplementedHashLibException(String.Format(CloneNotYetImplemented, Name));
        } // end function Clone

        virtual public IHashResult ComputeString(string a_data, Encoding encoding)
>>>>>>> Stashed changes
        {
            return ComputeBytes(Converters.ConvertStringToBytes(a_data, encoding));
        } // end function ComputeString

        public virtual IHashResult ComputeUntyped(IntPtr a_data, Int64 a_length)
        {
            Initialize();
            TransformUntyped(a_data, a_length);
            return TransformFinal();
        } // end function ComputeUntyped

        public virtual void TransformUntyped(IntPtr a_data, Int64 a_length)
        {
            unsafe
            {
                byte* PtrBuffer, PtrEnd;
                byte[] ArrBuffer = new byte[] { };
                Int32 LBufferSize;

                PtrBuffer = (byte*)a_data;

                LBufferSize = buffer_size > a_length ? BUFFER_SIZE : buffer_size;

                if (PtrBuffer != null)
                {
                    Array.Resize(ref ArrBuffer, LBufferSize);
                    PtrEnd = (PtrBuffer) + a_length;

                    while (PtrBuffer < PtrEnd)
                    {
                        if ((PtrEnd - PtrBuffer) >= LBufferSize)
                        {
                            fixed (byte* bDest = ArrBuffer)
                            {
                                Utils.Utils.memmove((IntPtr)bDest, (IntPtr)PtrBuffer, LBufferSize);
                            }

                            TransformBytes(ArrBuffer);
                            PtrBuffer += LBufferSize;
                        } // end if
                        else
                        {
                            Array.Resize(ref ArrBuffer, (int)(PtrEnd - PtrBuffer));
                            fixed (byte* bDest = ArrBuffer)
                            {
                                Utils.Utils.memmove((IntPtr)bDest, (IntPtr)PtrBuffer, ArrBuffer.Length);
                            }

                            TransformBytes(ArrBuffer);
                            break;
                        } // end else
                    } // end while
                } // end if
            }
        } // end function TransformUntyped

        public virtual IHashResult ComputeStream(Stream a_stream, Int64 a_length = -1)
        {
            Initialize();
            TransformStream(a_stream, a_length);
            return TransformFinal();
        } // end function ComputeStream

<<<<<<< Updated upstream
        public virtual IHashResult ComputeFile(string a_file_name,
		        Int64 a_from = 0, Int64 a_length = -1)
=======
        virtual public IHashResult ComputeFile(string a_file_name,
                Int64 a_from = 0, Int64 a_length = -1)
>>>>>>> Stashed changes
        {
            Initialize();
            TransformFile(a_file_name, a_from, a_length);
            return TransformFinal();
        } // end function ComputeFile

        public virtual IHashResult ComputeBytes(byte[] a_data)
        {
            Initialize();
            TransformBytes(a_data);
            return TransformFinal();
        } // end function ComputeBytes

        public virtual void TransformString(string a_data, Encoding encoding)
        {
            TransformBytes(Converters.ConvertStringToBytes(a_data, encoding));
        } // end function TransformString

        public virtual void TransformBytes(byte[] a_data)
        {
            TransformBytes(a_data, 0, a_data?.Length ?? 0);
        } // end function TransformBytes

        public virtual void TransformBytes(byte[] a_data, Int32 a_index)
        {
            if (a_data != null)
            {
                Int32 Length = a_data.Length - a_index;

                if (Length > 0) TransformBytes(a_data, a_index, Length);
            } // end if
        } // end function TransformBytes

        public abstract void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length);

<<<<<<< Updated upstream
	    public virtual void TransformStream(Stream a_stream, Int64 a_length = -1)
=======
        virtual public void TransformStream(Stream a_stream, Int64 a_length = -1)
>>>>>>> Stashed changes
        {
            Int32 readed = 0, LBufferSize;
            UInt64 size, new_size;
            Int64 total;

            total = 0;
            size = (UInt64)(a_stream?.Length ?? 0);

            if (a_stream != null)
            {
                if (a_length > -1)
                {
                    if ((UInt64)(a_stream.Position + a_length) > size)
                        throw new IndexOutOfRangeHashLibException(IndexOutOfRange);
                } // end if

                if (a_stream.Position >= (Int32)size)
                    return;
            } // end if
            else
                throw new ArgumentNilHashLibException(UnAssignedStream);

            if ((Int32)size > BUFFER_SIZE)
            {
                if (a_length == -1) LBufferSize = BUFFER_SIZE;
                else
                {
                    LBufferSize = (Int32)(a_length > BUFFER_SIZE ? BUFFER_SIZE : a_length);
                }
            }
            else
            {
                LBufferSize = (Int32)(a_length == -1 ? (Int32)size : a_length);
            }

            byte[] data = new byte[LBufferSize];

            if (LBufferSize == BUFFER_SIZE)
            {
                while (true)
                {
                    readed = a_stream.Read(data, 0, LBufferSize);

                    if (readed != BUFFER_SIZE)
                    {
                        Array.Resize(ref data, readed);

                        TransformBytes(data, 0, readed);

                        break;
                    }

                    if (readed == 0) break;

                    total = total + readed;

                    TransformBytes(data, 0, readed);

                    if (a_length != -1 && a_length - total <= BUFFER_SIZE)
                    {
                        new_size = (UInt64)(a_length - total);
                        Array.Resize(ref data, (int)new_size);

                        a_stream.Read(data, 0, (int)new_size);

                        TransformBytes(data, 0, (int)new_size);
                        break;
                    }
                } // end while
            }
            else
            {
                a_stream.Read(data, 0, LBufferSize);

                TransformBytes(data, 0, LBufferSize);
            }
        } // end function TransformStream

<<<<<<< Updated upstream
        public virtual void TransformFile(string a_file_name,
		        Int64 a_from = 0, Int64 a_length = -1)
=======
        virtual public void TransformFile(string a_file_name,
                Int64 a_from = 0, Int64 a_length = -1)
>>>>>>> Stashed changes
        {
            Stream ReadFile = File.OpenRead(a_file_name);

            if (!ReadFile.CanRead)
                throw new ArgumentHashLibException(FileNotExist);

            ReadFile.Position = 0;

            TransformStream(ReadFile, a_length);

            ReadFile.Close();
        } // end function TransformFile

        public abstract IHashResult TransformFinal();
    }
}