using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shadowsocks.Encryption.AEAD;

namespace Shadowsocks.Test
{
    [TestClass]
    public class AEADLegacyTest
    {
        [TestMethod]
        public void MasterKeyIsOwnedByEachEncryptorInstance()
        {
            const string method = "aes-256-gcm";
            byte[] salt = new byte[32];
            for (int i = 0; i < salt.Length; i++) salt[i] = (byte)i;
            byte[] plaintext = Encoding.ASCII.GetBytes("master-key-isolation");

            byte[] expected = EncryptOnce(method, "password-a", salt, plaintext);

            using (var first = new AEADOpenSSLEncryptor(method, "password-a"))
            using (var second = new AEADOpenSSLEncryptor(method, "password-b"))
            {
                // Constructing the second encryptor used to overwrite the static
                // master key subsequently consumed by the first instance.
                first.InitCipher(salt, true, false);
                byte[] actual = new byte[plaintext.Length + 16];
                uint actualLength = 0;
                first.cipherEncrypt(plaintext, (uint)plaintext.Length, actual, ref actualLength);

                Assert.AreEqual((uint)expected.Length, actualLength);
                CollectionAssert.AreEqual(expected, actual);
            }
        }


        [TestMethod]
        public void OpenSslContextCanBeRekeyedAcrossUdpPackets()
        {
            const string method = "aes-256-gcm";
            const string password = "udp-context-reuse";
            byte[] firstSalt = new byte[32];
            byte[] secondSalt = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                firstSalt[i] = (byte)i;
                secondSalt[i] = (byte)(0x80 + i);
            }
            byte[] plaintext = Encoding.ASCII.GetBytes("packet");
            byte[] expectedSecond = EncryptOnce(method, password, secondSalt, plaintext);

            using (var encryptor = new AEADOpenSSLEncryptor(method, password))
            {
                encryptor.InitCipher(firstSalt, true, true);
                byte[] scratch = new byte[plaintext.Length + 16];
                uint scratchLength = 0;
                encryptor.cipherEncrypt(plaintext, (uint)plaintext.Length, scratch, ref scratchLength);

                encryptor.InitCipher(secondSalt, true, true);
                byte[] actual = new byte[plaintext.Length + 16];
                uint actualLength = 0;
                encryptor.cipherEncrypt(plaintext, (uint)plaintext.Length, actual, ref actualLength);

                Assert.AreEqual((uint)expectedSecond.Length, actualLength);
                CollectionAssert.AreEqual(expectedSecond, actual);
            }
        }

        private static byte[] EncryptOnce(string method, string password, byte[] salt, byte[] plaintext)
        {
            using (var encryptor = new AEADOpenSSLEncryptor(method, password))
            {
                encryptor.InitCipher(salt, true, false);
                byte[] output = new byte[plaintext.Length + 16];
                uint length = 0;
                encryptor.cipherEncrypt(plaintext, (uint)plaintext.Length, output, ref length);
                Assert.AreEqual((uint)output.Length, length);
                return output;
            }
        }
    }
}
