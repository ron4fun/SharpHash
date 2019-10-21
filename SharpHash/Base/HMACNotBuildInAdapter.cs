using SharpHash.Interfaces;
using System;

namespace SharpHash.Base
{
    internal class HMACNotBuildInAdapter : Hash, IHMAC, IIHMACNotBuildIn, IWithKey,
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

        public void Clear()
        {
            Utils.Utils.memset(ref key, 0);
        } // end function Clear

<<<<<<< Updated upstream
        public override IHash Clone()
    	{
=======
        override public IHash Clone()
        {
>>>>>>> Stashed changes
            HMACNotBuildInAdapter hmac = new HMACNotBuildInAdapter(hash);
            hmac.blocksize = blocksize;

            if (opad != null)
            {
                hmac.opad = new byte[opad.Length];
                Utils.Utils.memcopy(ref hmac.opad, opad, opad.Length);
            } //

            if (ipad != null)
            {
                hmac.ipad = new byte[ipad.Length];
                Utils.Utils.memcopy(ref hmac.ipad, ipad, ipad.Length);
            } //

            if (key != null)
            {
                hmac.key = new byte[key.Length];
                Utils.Utils.memcopy(ref hmac.key, key, key.Length);
            } //

            return hmac;
        }

        public override void Initialize()
        {
            hash.Initialize();
            UpdatePads();
            hash.TransformBytes(ipad);
        } // end function Initialize

        public override IHashResult TransformFinal()
        {
            IHashResult result = hash.TransformFinal();
            hash.TransformBytes(opad);
            hash.TransformBytes(result.GetBytes());
            result = hash.TransformFinal();
            Initialize();

            return result;
        } // end function TransformFinal

        public override void TransformBytes(byte[] a_data, Int32 a_index, Int32 a_length)
        {
            hash.TransformBytes(a_data, a_index, a_length);
        } // end function TransformBytes

<<<<<<< Updated upstream
	    public override string Name => $"HMAC({hash.Name})";

	    public virtual byte[] Key
	    {
=======
        override public string Name
        {
            get
            {
                return $"HMAC({hash.Name})";
            }
        } // end property GetName

        virtual public byte[] Key
        {
>>>>>>> Stashed changes
            get
            {
                if (key != null)
                {
                    byte[] result = new byte[key.Length];
                    Utils.Utils.memcopy(ref result, key, key.Length);

                    return result;
                } //

                return new byte[0];
            }
            set
            {
                if (value == null || value.Length == 0)
                    key = new byte[0];
                else
                {
                    key = new byte[value.Length];
                    Utils.Utils.memcopy(ref key, value, value.Length);
                } // end else
            }
        } // end property Key

<<<<<<< Updated upstream
        public virtual Int32? KeyLength => null;
        
=======
        virtual public Int32? KeyLength
        {
            get
            {
                return null;
            }
        } // end property KeyLength

>>>>>>> Stashed changes
        protected void UpdatePads()
        {
            byte[] LKey;
            Int32 Idx;

            LKey = key.Length > blocksize ? hash.ComputeBytes(key).GetBytes() : key;

            unsafe
            {
                fixed (byte* ipadPtr = &ipad[0], opadPtr = &opad[0])
                {
                    Utils.Utils.memset((IntPtr)ipadPtr, 0x36, blocksize * sizeof(byte));
                    Utils.Utils.memset((IntPtr)opadPtr, 0x5C, blocksize * sizeof(byte));
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