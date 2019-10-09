using System;
using System.IO;
using SharpHash.Interfaces;
using SharpHash.Utils;

namespace SharpHash.Base
{
    public abstract class Hash : IHash
    {
        private Int32 buffer_size;
        protected Int32 block_size;
        protected Int32 hash_size;

        virtual public string GetName()
        {
            return this.GetType().Name;
        } // end function GetName

        virtual public Int32 GetBufferSize()
        {
            return buffer_size;
        } // end function GetBufferSize

        virtual public void SetBufferSize(Int32 value)
        { 
            if (value > 0)
            {
                buffer_size = value;
            } // end if
            else
            {
                throw new ArgumentHashLibException(InvalidBufferSize);
            } // end else
        } // end function SetBufferSize

        virtual public Int32 GetBlockSize()
        {
            return block_size;
        } // end function GetBlockSize

        virtual public Int32 GetHashSize()
        {
            return hash_size;
        } // end function GetHashSize

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

        virtual public IHash Clone()
	    {
		    throw new NotImplementedHashLibException(String.Format(CloneNotYetImplemented, GetName()));
	    }

	    virtual public IHashResult ComputeString(string a_data)
        {
            return ComputeBytes(Converters.ConvertStringToBytes(a_data));
        } // end function ComputeString

        virtual public IHashResult ComputeUntyped(IntPtr a_data, Int64 a_length)
        {
            Initialize();
            TransformUntyped(a_data, a_length);
            return TransformFinal();
        } // end function ComputeUntyped

        virtual public void TransformUntyped(IntPtr a_data, Int64 a_length)
        {
            unsafe {
                byte* PtrBuffer, PtrEnd;
                byte[] ArrBuffer = new byte[] { };
                Int32 LBufferSize;

                PtrBuffer = (byte*)a_data;

                if (buffer_size > a_length) // Sanity Check
                    LBufferSize = BUFFER_SIZE;
                else
                    LBufferSize = buffer_size;

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

        virtual public IHashResult ComputeStream(Stream a_stream, Int64 a_length = -1)
        {
            Initialize();
            TransformStream(a_stream, a_length);
            return TransformFinal();
        } // end function ComputeStream

        virtual public IHashResult ComputeFile(string a_file_name,
		        Int64 a_from = 0, Int64 a_length = -1)
        {
            Initialize();
            TransformFile(a_file_name, a_from, a_length);
            return TransformFinal();
        } // end function ComputeFile

        virtual public IHashResult ComputeBytes(byte[] a_data)
        {
            Initialize();
            TransformBytes(a_data);
            return TransformFinal();
        } // end function ComputeBytes

        virtual public void TransformString(string a_data)
        {
            TransformBytes(Converters.ConvertStringToBytes(a_data));
        } // end function TransformString

        virtual public void TransformBytes(byte[] a_data)
        {
            TransformBytes(a_data, 0, (Int32)a_data.Length);
        } // end function TransformBytes

        virtual public void TransformBytes(byte[] a_data, Int32 a_index)
        {
            Int32 Length = (Int32)a_data.Length - a_index;
            TransformBytes(a_data, a_index, Length);
        } // end function TransformBytes

        public abstract void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length);

	    virtual public void TransformStream(Stream a_stream, Int64 a_length = -1)
        {
            Int32 readed = 0, LBufferSize;
            UInt64 size, new_size;
            Int64 total;

            total = 0;
            size = (UInt64)a_stream.Length;

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

        virtual public void TransformFile(string a_file_name,
		        Int64 a_from = 0, Int64 a_length = -1)
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
