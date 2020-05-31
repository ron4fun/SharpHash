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

using SharpHash.Base;
using SharpHash.Crypto;
using SharpHash.Interfaces;
using SharpHash.Utils;
using System;

namespace SharpHash.KDF
{
    internal class PBKDF_Blake3NotBuiltInAdapter : KDFNotBuiltIn, IPBKDF_Blake3NotBuiltIn
    {
        private byte[] SrcKey;
        private IXOF Xof;

        private const Int32 derivationIVLen = 32;
        private const UInt32 flagDeriveKeyContext = 1 << 5;
        private const UInt32 flagDeriveKeyMaterial = 1 << 6;


        private PBKDF_Blake3NotBuiltInAdapter() {} // end cctr

        ~PBKDF_Blake3NotBuiltInAdapter()
        {
            Clear();
        }

        // derives a subkey from ctx and srcKey. ctx should be hardcoded,
        // globally unique, and application-specific. A good format for ctx strings is:
        //
        // [application] [commit timestamp] [purpose]
        //
        // e.g.:
        //
        // example.com 2019-12-25 16:18:03 session tokens v1
        //
        // The purpose of these requirements is to ensure that an attacker cannot trick
        // two different applications into using the same context string.
        internal unsafe PBKDF_Blake3NotBuiltInAdapter(byte[] srcKey, byte[] ctx)
        {
            if (srcKey == null) throw new ArgumentNullHashLibException(nameof(srcKey));
            if (ctx == null) throw new ArgumentNullHashLibException(nameof(ctx));

            SrcKey = srcKey.DeepCopy();

            UInt32[] ivWords = Blake3.IV.DeepCopy();

            // construct the derivation Hasher and get the derivationIV
            var derivationIv = new Blake3(derivationIVLen, ivWords, flagDeriveKeyContext)
                .ComputeBytes(ctx).GetBytes();

            fixed (byte* srcPtr = derivationIv)
            {
                fixed (UInt32* destPtr = ivWords)
                {
                    Converters.le32_copy((IntPtr)srcPtr, 0, (IntPtr)destPtr, 0, Blake3.KeyLengthInBytes);
                }
            }

            Xof = new Blake3XOF(32, ivWords, flagDeriveKeyMaterial);
        } // end cctr

        public override void Clear()
        {
            ArrayUtils.ZeroFill(ref SrcKey);
        } // end function Clear

        public override string ToString() => Name;

        public override IKDFNotBuiltIn Clone()
        {
            return new PBKDF_Blake3NotBuiltInAdapter()
            {
                SrcKey = SrcKey.DeepCopy(),
                Xof = (IXOF)Xof.Clone()
            };
        } // end function Clone

        public override byte[] GetBytes(Int32 byteCount)
        {
            var result = new byte[byteCount];
            Xof.XOFSizeInBits = (UInt64)byteCount * 8;
            Xof.Initialize();
            Xof.TransformBytes(SrcKey);
            // derive the SubKey
            Xof.DoOutput(ref result, 0, (UInt64)result.Length);
            Xof.Initialize();
            return result;
        }

        public override string Name => GetType().Name;

    } // end class PBKDF_Blake3NotBuiltInAdapter
}