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

using System;
using SharpHash.Interfaces.IBlake2BConfigurations;
using SharpHash.Utils;

namespace SharpHash.Crypto.Blake2BConfigurations
{
    public sealed class Blake2BIvBuilder
    {
        public static readonly string InvalidHashSize = "\"HashSize\" Must Be Greater Than 0 And Less Than or Equal To 64";
        public static readonly string InvalidKeyLength = "\"Key\" Length Must Not Be Greater Than 64";
        public static readonly string InvalidPersonalisationLength = "\"Personalisation\" Length Must Be Equal To 16";
        public static readonly string InvalidSaltLength = "\"Salt\" Length Must Be Equal To 16";
        public static readonly string TreeIncorrectInnerHashSize = "Tree Inner Hash Size Must Not Be Greater Than 64";

        public static unsafe UInt64[] ConfigB(IBlake2BConfig a_Config, IBlake2BTreeConfig a_TreeConfig)
	    {
		    bool isSequential;
            byte[] buffer = new byte[64];

            isSequential = a_TreeConfig == null;
		    if (isSequential)
                a_TreeConfig = Blake2BTreeConfig.GetSequentialTreeConfig();

            VerifyConfigB(a_Config, a_TreeConfig, isSequential);
            
		    buffer[0] = (byte)a_Config.HashSize;
            buffer[1] = (byte)(a_Config.Key?.Length ?? 0); ;

		    if (a_TreeConfig != null)
		    {
			    buffer[2] = a_TreeConfig.FanOut;
                buffer[3] = a_TreeConfig.MaxDepth;
                Converters.ReadUInt32AsBytesLE(a_TreeConfig.LeafSize, ref buffer, 4);
                Converters.ReadUInt64AsBytesLE(a_TreeConfig.NodeOffset, ref buffer, 8);
                buffer[16] = a_TreeConfig.NodeDepth;
                buffer[17] = a_TreeConfig.InnerHashSize;
            }

		    if (!a_Config.Salt.Empty())
			    Utils.Utils.Memmove(ref buffer, a_Config.Salt, 16 * sizeof(byte), 0, 32);

		    if (!a_Config.Personalisation.Empty())
                Utils.Utils.Memmove(ref buffer, a_Config.Personalisation, 16 * sizeof(byte), 0, 48);

            UInt64[] result = new UInt64[8];
            fixed (UInt64* resultPtr = result)
            {
                fixed (byte* bufferPtr = buffer)
                {
                    Converters.le64_copy((IntPtr)bufferPtr, 0, (IntPtr)resultPtr, 0, buffer.Length * sizeof(byte));
                }
            }

		    return result;
	    }

        private static void VerifyConfigB(IBlake2BConfig a_Config, IBlake2BTreeConfig a_TreeConfig, bool a_IsSequential)
        {
            // digest length
            if ((a_Config.HashSize <= 0) || (a_Config.HashSize > 64))
                throw new ArgumentOutOfRangeHashLibException(InvalidHashSize);

            // Key length
            if (!a_Config.Key.Empty())
            {
                if (a_Config.Key.Length > 64)
                    throw new ArgumentOutOfRangeHashLibException(InvalidKeyLength);
            }

            // Salt length
            if (!a_Config.Salt.Empty())
            {
                if (a_Config.Salt.Length != 16)
                    throw new ArgumentOutOfRangeHashLibException(InvalidSaltLength);
            }

            // Personalisation length
            if (!a_Config.Personalisation.Empty())
            {
                if (a_Config.Personalisation.Length != 16)
                    throw new ArgumentOutOfRangeHashLibException(InvalidPersonalisationLength);
            }

            // Tree InnerHashSize
            if (a_TreeConfig != null)
            {
                if ((a_IsSequential) && ((a_TreeConfig.InnerHashSize != 0)))
                {
                    throw new ArgumentOutOfRangeHashLibException("a_TreeConfig.TreeIntermediateHashSize");
                }

                if (a_TreeConfig.InnerHashSize > 64)
                {
                    throw new ArgumentOutOfRangeHashLibException(TreeIncorrectInnerHashSize);
                }
            }

        }

    } // end class Blake2BIvBuilder
}
