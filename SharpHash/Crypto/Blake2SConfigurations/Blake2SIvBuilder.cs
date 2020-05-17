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

using System;
using SharpHash.Interfaces.IBlake2SConfigurations;
using SharpHash.Utils;

namespace SharpHash.Crypto.Blake2SConfigurations
{
    public sealed class Blake2SIvBuilder
    {
        public static readonly string InvalidHashSize = "\"HashSize\" Must Be Greater Than 0 And Less Than or Equal To 32";
        public static readonly string InvalidKeyLength = "\"Key\" Length Must Not Be Greater Than 32";
        public static readonly string InvalidPersonalisationLength = "\"Personalisation\" Length Must Be Equal To 8";
        public static readonly string InvalidSaltLength = "\"Salt\" Length Must Be Equal To 8";
        public static readonly string TreeIncorrectInnerHashSize = "Tree Inner Hash Size Must Not Be Greater Than 32";

        public static unsafe UInt32[] ConfigS(IBlake2SConfig a_Config, IBlake2STreeConfig a_TreeConfig)
	    {
		    bool isSequential;
            byte[] buffer = new byte[32];

            isSequential = a_TreeConfig == null;
		    if (isSequential)
                a_TreeConfig = Blake2STreeConfig.GetSequentialTreeConfig();

            VerifyConfigS(a_Config, a_TreeConfig, isSequential);
            
		    buffer[0] = (byte)a_Config.HashSize;
            buffer[1] = (byte)(a_Config.Key?.Length ?? 0);

		    if (a_TreeConfig != null)
		    {
			    buffer[2] = a_TreeConfig.FanOut;
                buffer[3] = a_TreeConfig.MaxDepth;
                Converters.ReadUInt32AsBytesLE(a_TreeConfig.LeafSize, ref buffer, 4);
			    buffer[8] = (byte)a_TreeConfig.NodeOffset;
			    buffer[9] = (byte)(a_TreeConfig.NodeOffset >> 8);
			    buffer[10] = (byte)(a_TreeConfig.NodeOffset >> 16);
			    buffer[11] = (byte)(a_TreeConfig.NodeOffset >> 24);
			    buffer[12] = (byte)(a_TreeConfig.NodeOffset >> 32);
			    buffer[13] = (byte)(a_TreeConfig.NodeOffset >> 40);
			    buffer[14] = a_TreeConfig.NodeDepth;
                buffer[15] = a_TreeConfig.InnerHashSize;
            }

		    if (!a_Config.Salt.Empty())
			    Utils.Utils.Memmove(ref buffer, a_Config.Salt, 8 * sizeof(byte), 0, 16);

		    if (!a_Config.Personalisation.Empty())
                Utils.Utils.Memmove(ref buffer, a_Config.Personalisation, 8 * sizeof(byte), 0, 24);

            UInt32[] result = new UInt32[8];
            fixed (UInt32* resultPtr = result)
            {
                fixed (byte* bufferPtr = buffer)
                {
                    Converters.le32_copy((IntPtr)bufferPtr, 0, (IntPtr)resultPtr, 0, buffer.Length * sizeof(byte));
                }
            }

		    return result;
	    }

        private static void VerifyConfigS(IBlake2SConfig a_Config, IBlake2STreeConfig a_TreeConfig, bool a_IsSequential)
        {
            // digest length
            if ((a_Config.HashSize <= 0) || (a_Config.HashSize > 32))
                throw new ArgumentOutOfRangeHashLibException(InvalidHashSize);

            // Key length
            if (!a_Config.Key.Empty())
            {
                if (a_Config.Key.Length > 32)
                    throw new ArgumentOutOfRangeHashLibException(InvalidKeyLength);
            }

            // Salt length
            if (!a_Config.Salt.Empty())
            {
                if (a_Config.Salt.Length != 8)
                    throw new ArgumentOutOfRangeHashLibException(InvalidSaltLength);
            }

            // Personalisation length
            if (!a_Config.Personalisation.Empty())
            {
                if (a_Config.Personalisation.Length != 8)
                    throw new ArgumentOutOfRangeHashLibException(InvalidPersonalisationLength);
            }

            // Tree InnerHashSize
            if (a_TreeConfig != null)
            {
                if ((a_IsSequential) && ((a_TreeConfig.InnerHashSize != 0)))
                {
                    throw new ArgumentOutOfRangeHashLibException("a_TreeConfig.TreeIntermediateHashSize");
                }

                if (a_TreeConfig.InnerHashSize > 32)
                {
                    throw new ArgumentOutOfRangeHashLibException(TreeIncorrectInnerHashSize);
                }
            }

        }
    } // end class Blake2SIvBuilder
}
