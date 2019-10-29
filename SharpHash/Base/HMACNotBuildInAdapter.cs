///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2019  Mbadiwe Nnaemeka Ronald
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
using System;

namespace SharpHash.Base
{
    internal class HMACNotBuildInAdapter : Hash, IHMAC, IIHMACNotBuildIn, IWithKey,
        ICrypto, ICryptoNotBuildIn
    {
        private IHash hash = null;
        private byte[] opad = null, ipad = null, key = null;

        private HMACNotBuildInAdapter(IHash a_underlyingHash, byte[] a_HMACKey)
            : base(a_underlyingHash.HashSize, a_underlyingHash.BlockSize)
        {
            hash = a_underlyingHash.Clone();
            Key = a_HMACKey;
            ipad = new byte[hash.BlockSize];
            opad = new byte[hash.BlockSize];
        } // end constructor

        public static IHMAC CreateHMAC(IHash a_Hash, byte[] a_HMACKey)
        {
            if (a_Hash is IHMAC)
                return a_Hash as IHMAC;

            return new HMACNotBuildInAdapter(a_Hash, a_HMACKey);
        } //

        public void Clear()
        {
            Utils.Utils.memset(ref key, 0);
        } // end function Clear

        public override IHash Clone()
        {
            HMACNotBuildInAdapter hmac = new HMACNotBuildInAdapter(hash, Key);

            hmac.opad = new byte[opad?.Length ?? 0];
            if (!(opad == null || opad.Length == 0))
            {
                Utils.Utils.memcopy(ref hmac.opad, opad, opad.Length);
            } //

            hmac.ipad = new byte[ipad?.Length ?? 0];
            if (!(ipad == null || ipad.Length == 0))
            {
                Utils.Utils.memcopy(ref hmac.ipad, ipad, ipad.Length);
            } //

            hmac.key = new byte[key?.Length ?? 0];
            if (!(key == null || key.Length == 0))
            {
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

        public override string Name => $"HMAC({hash.Name})";

        public virtual byte[] Key
        {
            get
            {
                byte[] result = new byte[key?.Length ?? 0];
                if (!(key == null || key.Length == 0))
                {
                    Utils.Utils.memcopy(ref result, key, key.Length);
                } //

                return result;
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

        public virtual Int32? KeyLength => null;

        protected void UpdatePads()
        {
            byte[] LKey;
            Int32 Idx;

            LKey = Key.Length > hash.BlockSize ? hash.ComputeBytes(Key).GetBytes() : Key;

            Utils.Utils.memset(ref ipad, 0x36);
            Utils.Utils.memset(ref opad, 0x5C);

            Idx = 0;
            while ((Idx < LKey.Length) && (Idx < hash.BlockSize))
            {
                ipad[Idx] = (byte)(ipad[Idx] ^ LKey[Idx]);
                opad[Idx] = (byte)(opad[Idx] ^ LKey[Idx]);
                Idx++;
            } // end while
        } // end function UpdatePads
    }
}