using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace OpenSSLCompat
{
    public class OpenSSHKeygen
    {
        public static RSAParameters GenerateKeyPair()
        {
            return GenerateKeyPair(4096);
        }

        public static RSAParameters GenerateKeyPair(int keySize)
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = keySize;
                return rsa.ExportParameters(true);
            }
        }

        public static String ExportPrivateKeyPKCS1(RSAParameters keyInfo)
        {
            var (buffer, length) = GetPrivateKeyBytes(keyInfo);
            return ExportPrivateKeyPKCS1(buffer, length);
        }

        public static String ExportPublicKeyPKCS1(RSAParameters keyInfo)
        {
            var (buffer, length) = GetPublicKeyBytes(keyInfo);
            return ExportPublicKeyPKCS1(buffer, length);
        }

        public static String ExportPublicKeyOpenSSH(RSAParameters keyInfo, String comment = null)
        {
            using (var writer = new StringWriter())
            {
                byte[] buffer;
                int length;
                using (var innerStream = new MemoryStream())
                using (var innerWriter = new BinaryWriter(innerStream))
                {
                    var sshRsaBytes = Encoding.ASCII.GetBytes("ssh-rsa");
                    WriteLengthNetworkOrder(innerWriter, sshRsaBytes.Length);
                    innerWriter.Write(sshRsaBytes);

                    WriteMPint(innerWriter, keyInfo.Exponent);
                    WriteMPint(innerWriter, keyInfo.Modulus);

                    innerWriter.Flush();
                    buffer = innerStream.GetBuffer();
                    length = (int)innerStream.Length;
                }

                writer.Write("ssh-rsa ");
                writer.Write(Convert.ToBase64String(buffer, 0, length));

                if (!String.IsNullOrEmpty(comment))
                {
                    writer.Write(' ');
                    writer.Write(comment);
                }

                return writer.ToString();
            }
        }

        // PKCS#1 PEM
        private static (byte[] Buffer, int Length) GetPrivateKeyBytes(RSAParameters keyInfo)
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                using (var innerWriter = new BinaryWriter(innerStream))
                {
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, keyInfo.Modulus);
                    EncodeIntegerBigEndian(innerWriter, keyInfo.Exponent);
                    EncodeIntegerBigEndian(innerWriter, keyInfo.D);
                    EncodeIntegerBigEndian(innerWriter, keyInfo.P);
                    EncodeIntegerBigEndian(innerWriter, keyInfo.Q);
                    EncodeIntegerBigEndian(innerWriter, keyInfo.DP);
                    EncodeIntegerBigEndian(innerWriter, keyInfo.DQ);
                    EncodeIntegerBigEndian(innerWriter, keyInfo.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                return (stream.GetBuffer(), (int)stream.Length);
            }
        }

        // Detailed explanation of PKCS#1 notation of key
        // https://stackoverflow.com/a/29707204/572002
        // PKCS#1 PEM
        private static (byte[] Buffer, int Length) GetPublicKeyBytes(RSAParameters keyInfo)
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                using (var innerWriter = new BinaryWriter(innerStream))
                {
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 }; // 1.2.840.113549.1.1.1
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    using (var bitStringWriter = new BinaryWriter(bitStringStream))
                    {
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        using (var paramsWriter = new BinaryWriter(paramsStream))
                        {
                            EncodeIntegerBigEndian(paramsWriter, keyInfo.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, keyInfo.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                return (stream.GetBuffer(), (int)stream.Length);
            }
        }

        private static String ExportPrivateKeyPKCS1(byte[] buffer, int length)
        {
            return ExportPEM(
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----END RSA PRIVATE KEY-----",
                buffer, length);
        }

        private static String ExportPublicKeyPKCS1(byte[] buffer, int length)
        {
            return ExportPEM(
                "-----BEGIN PUBLIC KEY-----",
                "-----END PUBLIC KEY-----",
                buffer, length);
        }

        private static String ExportPEM(String header, String footer, byte[] buffer, int length)
        {
            using (var writer = new StringWriter())
            {
                var base64 = Convert.ToBase64String(buffer, 0, length).ToCharArray();

                writer.Write(header);
                writer.Write('\n');

                for (var i = 0; i < base64.Length; i += 64)
                {
                    writer.Write(base64, i, Math.Min(64, base64.Length - i));
                    writer.Write('\n');
                }

                writer.Write(footer);
                writer.Write('\n');

                writer.Flush();
                return writer.ToString();
            }
        }

        private static void WriteMPint(BinaryWriter writer, byte[] buffer)
        {
            var isSigned = (buffer[0] & (byte)0x80) != 0;
            var length = buffer.Length;

            if (isSigned)
            {
                length++;
            }

            WriteLengthNetworkOrder(writer, length);

            if (isSigned)
            {
                // write extra BYTE (not int)
                writer.Write((byte)0);
            }

            writer.Write(buffer);
        }

        // encode lengths as 32bit unsigned in network byte order
        private static void WriteLengthNetworkOrder(BinaryWriter writer, int length)
        {
            UInt32 temp = Convert.ToUInt32(length);

            var bytes = new byte[4];
            bytes[0] = (byte)((temp >> 24) & 0xFF);
            bytes[1] = (byte)((temp >> 16) & 0xFF);
            bytes[2] = (byte)((temp >> 8) & 0xFF);
            bytes[3] = (byte)((temp) & 0xFF);

            writer.Write(bytes);
        }

        // ASN.1
        private static void EncodeLength(BinaryWriter writer, int length)
        {
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            }

            if (length < 0x80)
            {
                // Short form
                writer.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                writer.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    writer.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        // ASN.1
        private static void EncodeIntegerBigEndian(BinaryWriter writer, byte[] value, bool forceUnsigned = true)
        {
            writer.Write((byte)0x02); // INTEGER

            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0)
                {
                    break;
                }
                prefixZeros++;
            }

            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(writer, 1);
                writer.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(writer, value.Length - prefixZeros + 1);
                    writer.Write((byte)0);
                }
                else
                {
                    EncodeLength(writer, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    writer.Write(value[i]);
                }
            }
        }
    }
}
