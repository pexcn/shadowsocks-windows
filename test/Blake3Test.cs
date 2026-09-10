using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shadowsocks.Encryption;

namespace Shadowsocks.Test
{
    /// <summary>
    /// Smoke tests for the libsscrypto BLAKE3 binding. These are upstream's own
    /// derive_key vectors: if they pass, the P/Invoke signatures, the
    /// caller-allocated hasher and the context-length handling are all right,
    /// which separates "BLAKE3 is wrong" from "we fed it the wrong bytes" when
    /// a SIP022 handshake fails.
    /// </summary>
    [TestClass]
    public class Blake3Test
    {
        private static readonly byte[] TestVectorContext =
            Encoding.ASCII.GetBytes("BLAKE3 2019-12-27 16:29:52 test vectors context");

        private static string Hex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", string.Empty).ToLowerInvariant();
        }

        [TestMethod]
        public void TestDeriveKeyEmptyInput()
        {
            byte[] output = new byte[32];
            Blake3.DeriveKey(TestVectorContext, new byte[0], output);
            Assert.AreEqual("2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d",
                Hex(output));
        }

        [TestMethod]
        public void TestDeriveKeySingleByteInput()
        {
            byte[] output = new byte[32];
            Blake3.DeriveKey(TestVectorContext, new byte[1], output);
            Assert.AreEqual("b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c",
                Hex(output));
        }

        /// <summary>
        /// BLAKE3 is an XOF, so a 16-byte output must be the prefix of the
        /// 32-byte one. This is what lets 2022-blake3-aes-128-gcm ask for a
        /// short subkey with no truncation step of its own.
        /// </summary>
        [TestMethod]
        public void TestShortOutputIsAPrefix()
        {
            byte[] full = new byte[32];
            byte[] half = new byte[16];
            Blake3.DeriveKey(TestVectorContext, new byte[1], full);
            Blake3.DeriveKey(TestVectorContext, new byte[1], half);
            Assert.AreEqual(Hex(full).Substring(0, 32), Hex(half));
        }

        /// <summary>
        /// PSK || salt fed as two updates must equal the same bytes fed as one.
        /// </summary>
        [TestMethod]
        public void TestSessionSubkeyMatchesConcatenatedMaterial()
        {
            byte[] context = Encoding.ASCII.GetBytes("shadowsocks 2022 session subkey");
            byte[] psk = new byte[32];
            byte[] salt = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                psk[i] = (byte)i;
                salt[i] = (byte)(0xff - i);
            }

            byte[] material = new byte[64];
            Buffer.BlockCopy(psk, 0, material, 0, 32);
            Buffer.BlockCopy(salt, 0, material, 32, 32);

            byte[] viaDeriveKey = new byte[32];
            byte[] viaSessionSubkey = new byte[32];
            Blake3.DeriveKey(context, material, viaDeriveKey);
            Blake3.DeriveSessionSubkey(psk, salt, viaSessionSubkey);

            Assert.AreEqual(Hex(viaDeriveKey), Hex(viaSessionSubkey));
        }
    }
}
