using SharpHash.Interfaces;
using System;

namespace SharpHash.Base
{
    public class HMACNotBuildInAdapter : Hash, IHMAC, IIHMACNotBuildIn, IWithKey,
        ICrypto, ICryptoNotBuildIn
    {
        private IHash hash = null;
        private byte[] opad = null, ipad = null, key = null;
        private Int32 blocksize;

        public HMACNotBuildInAdapter(IHash a_underlyingHash) 
            : base(a_underlyingHash.HashSize, a_underlyingHash.BlockSize)
        {
            hash = a_underlyingHash.Clone();
            blocksize = hash.BlockSize;
            key = new byte[0];
            ipad = new byte[blocksize];
            opad = new byte[blocksize];
        } // end constructor

        override public IHash Clone()
    	{
            HMACNotBuildInAdapter hmac = new HMACNotBuildInAdapter(hash);
            hmac.blocksize = blocksize;
		    hmac.opad = opad;
		    hmac.ipad = ipad;
		    hmac.key = key;

		    return hmac;
	    }

        override public void Initialize()
        {
            hash.Initialize();
            UpdatePads();
            hash.TransformBytes(ipad);
        } // end function Initialize

        override public IHashResult TransformFinal()
        {
            IHashResult result = hash.TransformFinal();
            hash.TransformBytes(opad);
            hash.TransformBytes(result.GetBytes());
            result = hash.TransformFinal();
            Initialize();

            return result;
        } // end function TransformFinal

        override public void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            hash.TransformBytes(a_data, a_index, a_length);
        } // end function TransformBytes

	    override public string Name
	    {
            get
            {
                return $"HMAC({hash.Name})";
            }
	    } // end property GetName

	    virtual public byte[] Key
	    {
            get
            {
                return key;
            }
            set
            {
                if (value == null || value.Length == 0)
                    key = new byte[0];
                else
                    key = value;
            }
        } // end property Key

        virtual public Int32? KeyLength
	    {
            get
            {
                return null;
            }
        } // end property KeyLength
        
        protected void UpdatePads()
        {
            byte[] LKey;
            Int32 Idx;

            if (key.Length > blocksize)
            {
                LKey = hash.ComputeBytes(key).GetBytes();
            } // end if
            else
            {
                LKey = key;
            } // end else

            unsafe
            {
                fixed (byte* ipadPtr = &ipad[0], opadPtr = &opad[0])
                {
                    Utils.Utils.memset((IntPtr)ipadPtr, (char)0x36, blocksize * sizeof(byte));
                    Utils.Utils.memset((IntPtr)opadPtr, (char)0x5C, blocksize * sizeof(byte));
                }
            }
           
            Idx = 0;
            while ((Idx < LKey.Length) && (Idx < blocksize))
            {
                ipad[Idx] = (byte)(ipad[Idx] ^ LKey[Idx]);
                opad[Idx] = (byte)(opad[Idx] ^ LKey[Idx]);
                Idx++;
            } // end while
        } // end function UpdatePads

    }
}
