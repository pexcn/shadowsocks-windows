using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shadowsocks.Encryption;
using Shadowsocks.Encryption.AEAD;
using Shadowsocks.Encryption.Exception;

namespace Shadowsocks.Test
{
    [TestClass]
    public class AEAD2022InteropTest
    {
        private const long FixedTime = 1700000000L;
        private static readonly byte[] Address = { 0x01, 0x01, 0x02, 0x03, 0x04, 0x1f, 0x90 };
        private static readonly byte[] RequestInput = Address.Concat(Encoding.ASCII.GetBytes("hello")).ToArray();
        private static readonly byte[] ResponsePayload = Encoding.ASCII.GetBytes("world");
        private static readonly byte[] UdpResponse = Address.Concat(ResponsePayload).ToArray();
        private static readonly byte[] ClientSessionId = Enumerable.Range(0, 8).Select(i => (byte)i).ToArray();

        private sealed class Vector
        {
            public string Method;
            public string Key;
            public string TcpRequest;
            public string TcpResponse;
            public string UdpRequest;
            public string UdpResponse;
        }

        // These byte strings were generated outside this codebase with an
        // independent BLAKE3 derive-key implementation plus AES-GCM/ChaCha20-
        // Poly1305/XChaCha20-Poly1305 primitives. They are constants on purpose:
        // production code cannot accidentally regenerate a matching wrong wire.
        private static readonly Dictionary<string, Vector> Vectors = new Dictionary<string, Vector>
        {
            ["2022-blake3-aes-128-gcm"] = new Vector
            {
                Method = "2022-blake3-aes-128-gcm",
                Key = "AAECAwQFBgcICQoLDA0ODw==",
                TcpRequest = "000102030405060708090a0b0c0d0e0f35862b4f511b18084f6b4024f70de3332586b3874f7638d356e53a45f263391d28f3b618600f4ada9b34ee2994973cab2cd5fce5e69b6bc780",
                TcpResponse = "808182838485868788898a8b8c8d8e8fa242d2422f3788104ccf8e444e8e4f23eac6f5a15d18cd83bbb75d8a1213d408cb534f7feb2cd990353d175db7a7578ff7e6a54eec131f24fe7733104c8adacc",
                UdpRequest = "9dc28337d6d3b4be380dd72d8e5cc1a5826ef18c3e8d19a6211e3d65e99abb26eb9b359aed36a6fc0a9040f972955c3ba10c39e9dc76c4",
                UdpResponse = "db28949c3eadbd60670bfcef2d6079cfa4e04c4fb0bcda5763e13fa9bd360a64864ccc35b51ec3d1ee894233c80466da91f3bb743c7d2b218e587bfe6382d7"
            },
            ["2022-blake3-aes-256-gcm"] = new Vector
            {
                Method = "2022-blake3-aes-256-gcm",
                Key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                TcpRequest = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f8ad2318b967481973d90b1fc5c5c8a71632ecda49510a414f786ace1fa7cc37e6de1d841f89d22853170e3a1a0d2510f25ac5ebb995b256839",
                TcpResponse = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f4fe13038514af6dc2b5918ef0e43afbebd8db3df80092366e6a9b83e47cd519988de2918bd33e000019b1ca9947b87008a04e1bf60697c8bec58c410252812e23265ed43a6be814fd77ad909be4cc2ca",
                UdpRequest = "15a77748ec643a1a2a351261464309a7cca0cf3d3a0de0a5d65acd44446eda81c24b3889cdf71994e0f8a66cb82535e30b8d626d61e55e",
                UdpResponse = "de7c7b459df4467f8ed826aec7b90d4032cd10e55487da79078613c1105c6b10f872b8d70cab95e2902f13c6b2b47ea488275ad98fe6d54f462a9677b14ee1"
            },
            ["2022-blake3-chacha20-poly1305"] = new Vector
            {
                Method = "2022-blake3-chacha20-poly1305",
                Key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                TcpRequest = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f9f2a5c3e72a7e6373487bf17ee1dea3955bc293d6886ff989dd9e1c5375563639ed9eaf6b1a5f93ffff14387238ee2dfc55e7e27ec6afa8c08",
                TcpResponse = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f3a39f1281acc419b3de8cce616b97632df06641a21e28fa0d5ffd5c8a8966e47e0a0457ed42e86cfcae084d6b5cb2a30e3aed8abb1ef40313926556078e87141b0a99111c6529c3504094aa769bb7567",
                UdpRequest = "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f052fcf122945e97e4eb0b5f91bb546c1f2c906463e19c24887a016ee8ac33a601c30a447afc5d8abedb419d55df7bf3818ae714a1b8485",
                UdpResponse = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7503f287038b33334e5c3daf754682db0a30d4b538cdde992581098ae6d63f8bdca76961cc3021c9da334f34f6e2f787459cf23779a57e096b229704ac49b1f"
            }
        };

        private sealed class Clock
        {
            public long Now = FixedTime;
        }

        private sealed class DeterministicRandom
        {
            private int _next;

            public void Fill(byte[] buffer, int length)
            {
                for (int i = 0; i < length; i++)
                {
                    buffer[i] = (byte)_next++;
                }
            }
        }

        [TestMethod]
        [DataRow("2022-blake3-aes-128-gcm")]
        [DataRow("2022-blake3-aes-256-gcm")]
        [DataRow("2022-blake3-chacha20-poly1305")]
        public void TcpRequestMatchesIndependentWireVector(string method)
        {
            Vector v = Vectors[method];
            using (var client = CreateClient(v, new Clock()))
            {
                byte[] output = new byte[4096];
                client.Encrypt(RequestInput, RequestInput.Length, output, out int length);
                CollectionAssert.AreEqual(Hex(v.TcpRequest), output.Take(length).ToArray());
            }
        }

        [TestMethod]
        [DataRow("2022-blake3-aes-128-gcm")]
        [DataRow("2022-blake3-aes-256-gcm")]
        [DataRow("2022-blake3-chacha20-poly1305")]
        public void TcpResponseIndependentWireVectorDecrypts(string method)
        {
            Vector v = Vectors[method];
            using (var client = CreateClient(v, new Clock()))
            {
                PrimeTcpRequest(client);
                byte[] response = Hex(v.TcpResponse);
                byte[] output = new byte[1024];
                client.Decrypt(response, response.Length, output, out int length);
                CollectionAssert.AreEqual(ResponsePayload, output.Take(length).ToArray());
            }
        }

        [TestMethod]
        [DataRow("2022-blake3-aes-128-gcm")]
        [DataRow("2022-blake3-aes-256-gcm")]
        [DataRow("2022-blake3-chacha20-poly1305")]
        public void UdpIndependentWireVectorsRoundTrip(string method)
        {
            Vector v = Vectors[method];
            using (var client = CreateClient(v, new Clock()))
            {
                byte[] request = new byte[4096];
                client.EncryptUDP(RequestInput, RequestInput.Length, request, out int requestLength);
                CollectionAssert.AreEqual(Hex(v.UdpRequest), request.Take(requestLength).ToArray());

                byte[] response = Hex(v.UdpResponse);
                byte[] output = new byte[1024];
                client.DecryptUDP(response, response.Length, output, out int responseLength);
                CollectionAssert.AreEqual(UdpResponse, output.Take(responseLength).ToArray());
            }
        }

        [TestMethod]
        [DataRow("2022-blake3-aes-128-gcm")]
        [DataRow("2022-blake3-aes-256-gcm")]
        [DataRow("2022-blake3-chacha20-poly1305")]
        public void TcpResponseCanArriveOneByteAtATime(string method)
        {
            Vector v = Vectors[method];
            using (var client = CreateClient(v, new Clock()))
            {
                PrimeTcpRequest(client);
                byte[] response = Hex(v.TcpResponse);
                var plaintext = new List<byte>();
                for (int i = 0; i < response.Length; i++)
                {
                    byte[] one = { response[i] };
                    byte[] output = new byte[1024];
                    client.Decrypt(one, 1, output, out int length);
                    plaintext.AddRange(output.Take(length));
                }
                CollectionAssert.AreEqual(ResponsePayload, plaintext.ToArray());
            }
        }

        [TestMethod]
        public void TcpAcceptsZeroOneAndMaximumLengthChunks()
        {
            Vector v = Vectors["2022-blake3-aes-128-gcm"];
            var clock = new Clock();
            using (var client = CreateClient(v, clock))
            {
                PrimeTcpRequest(client);
                byte[] one = { 0x42 };
                byte[] max = Enumerable.Range(0, 0xffff).Select(i => (byte)i).ToArray();
                byte[] response = BuildTcpServerResponse(v, clock.Now,
                    new[] { Array.Empty<byte>(), one, max }, 1, null);
                byte[] output = new byte[0x10000];
                client.Decrypt(response, response.Length, output, out int length);
                Assert.AreEqual(0x10000, length);
                Assert.AreEqual((byte)0x42, output[0]);
                CollectionAssert.AreEqual(max, output.Skip(1).Take(max.Length).ToArray());
            }
        }

        [TestMethod]
        public void TcpRejectsDamagedTagAndWrongResponseHeader()
        {
            Vector v = Vectors["2022-blake3-aes-128-gcm"];
            var clock = new Clock();

            using (var client = CreateClient(v, clock))
            {
                PrimeTcpRequest(client);
                byte[] damaged = Hex(v.TcpResponse);
                damaged[damaged.Length - 1] ^= 0x80;
                Assert.ThrowsExactly<CryptoErrorException>(() =>
                {
                    client.Decrypt(damaged, damaged.Length, new byte[1024], out _);
                });
            }

            using (var client = CreateClient(v, clock))
            {
                PrimeTcpRequest(client);
                byte[] wrongType = BuildTcpServerResponse(v, clock.Now,
                    new[] { ResponsePayload }, 0, null);
                Assert.ThrowsExactly<CryptoErrorException>(() =>
                {
                    client.Decrypt(wrongType, wrongType.Length, new byte[1024], out _);
                });
            }

            using (var client = CreateClient(v, clock))
            {
                PrimeTcpRequest(client);
                byte[] wrongSalt = Enumerable.Repeat((byte)0xee, KeyLength(v)).ToArray();
                byte[] wrongEcho = BuildTcpServerResponse(v, clock.Now,
                    new[] { ResponsePayload }, 1, wrongSalt);
                Assert.ThrowsExactly<CryptoErrorException>(() =>
                {
                    client.Decrypt(wrongEcho, wrongEcho.Length, new byte[1024], out _);
                });
            }
        }

        [TestMethod]
        [DataRow("2022-blake3-aes-128-gcm")]
        [DataRow("2022-blake3-aes-256-gcm")]
        [DataRow("2022-blake3-chacha20-poly1305")]
        public void UdpRejectsTruncationBadTagPaddingAndEchoWithoutAdvancingReplayState(string method)
        {
            Vector v = Vectors[method];
            var clock = new Clock();
            using (var client = CreateClient(v, clock))
            {
                PrimeUdpRequest(client);
                byte[] valid = BuildUdpServerPacket(v, clock.Now, 0xa0, 7, UdpResponse, 0, false);

                byte[] truncated = valid.Take(IsAes(v) ? 20 : 30).ToArray();
                Assert.ThrowsExactly<CryptoErrorException>(() =>
                    client.DecryptUDP(truncated, truncated.Length, new byte[1024], out _));

                byte[] damaged = (byte[])valid.Clone();
                damaged[damaged.Length - 1] ^= 1;
                Assert.ThrowsExactly<CryptoErrorException>(() =>
                    client.DecryptUDP(damaged, damaged.Length, new byte[1024], out _));

                byte[] badPadding = BuildUdpServerPacket(v, clock.Now, 0xa0, 7,
                    Array.Empty<byte>(), 64, false, actualPaddingLength: 0);
                Assert.ThrowsExactly<CryptoErrorException>(() =>
                    client.DecryptUDP(badPadding, badPadding.Length, new byte[1024], out _));

                byte[] badEcho = BuildUdpServerPacket(v, clock.Now, 0xa0, 7,
                    UdpResponse, 0, true);
                Assert.ThrowsExactly<CryptoErrorException>(() =>
                    client.DecryptUDP(badEcho, badEcho.Length, new byte[1024], out _));

                Assert.ThrowsExactly<CryptoErrorException>(() =>
                    client.DecryptUDP(valid, valid.Length, new byte[1], out _));

                // Authentication/header/output failures above must not consume packet id 7.
                byte[] output = new byte[1024];
                client.DecryptUDP(valid, valid.Length, output, out int length);
                CollectionAssert.AreEqual(UdpResponse, output.Take(length).ToArray());
            }
        }

        [TestMethod]
        [DataRow("2022-blake3-aes-128-gcm")]
        [DataRow("2022-blake3-aes-256-gcm")]
        [DataRow("2022-blake3-chacha20-poly1305")]
        public void UdpSlidingWindowAcceptsOutOfOrderAndRejectsDuplicate(string method)
        {
            Vector v = Vectors[method];
            var clock = new Clock();
            using (var client = CreateClient(v, clock))
            {
                PrimeUdpRequest(client);
                foreach (ulong packetId in new ulong[] { 5, 3, 4 })
                {
                    byte[] packet = BuildUdpServerPacket(v, clock.Now, 0xa0, packetId,
                        new[] { (byte)packetId }, 0, false);
                    client.DecryptUDP(packet, packet.Length, new byte[64], out int length);
                    Assert.AreEqual(1, length);
                }

                byte[] duplicate = BuildUdpServerPacket(v, clock.Now, 0xa0, 3,
                    new byte[] { 3 }, 0, false);
                Assert.ThrowsExactly<CryptoErrorException>(() =>
                    client.DecryptUDP(duplicate, duplicate.Length, new byte[64], out _));
            }
        }

        [TestMethod]
        [DataRow("2022-blake3-aes-128-gcm")]
        [DataRow("2022-blake3-aes-256-gcm")]
        [DataRow("2022-blake3-chacha20-poly1305")]
        public void UdpDoesNotForgetOldReplayWindowDuringRapidSessionRotation(string method)
        {
            Vector v = Vectors[method];
            var clock = new Clock();
            using (var client = CreateClient(v, clock))
            {
                PrimeUdpRequest(client);
                byte[] a = BuildUdpServerPacket(v, clock.Now, 0xa0, 0, new byte[] { 1 }, 0, false);
                byte[] b = BuildUdpServerPacket(v, clock.Now, 0xb0, 0, new byte[] { 2 }, 0, false);
                byte[] c = BuildUdpServerPacket(v, clock.Now, 0xc0, 0, new byte[] { 3 }, 0, false);

                client.DecryptUDP(a, a.Length, new byte[64], out _);
                client.DecryptUDP(b, b.Length, new byte[64], out _);

                Assert.ThrowsExactly<CryptoErrorException>(() =>
                    client.DecryptUDP(c, c.Length, new byte[64], out _));
                Assert.ThrowsExactly<CryptoErrorException>(() =>
                    client.DecryptUDP(a, a.Length, new byte[64], out _));

                clock.Now += 61;
                byte[] cAfterExpiry = BuildUdpServerPacket(v, clock.Now, 0xc0, 1,
                    new byte[] { 4 }, 0, false);
                client.DecryptUDP(cAfterExpiry, cAfterExpiry.Length, new byte[64], out int length);
                Assert.AreEqual(1, length);
            }
        }

        private static AEAD2022Encryptor CreateClient(Vector v, Clock clock)
        {
            var random = new DeterministicRandom();
            return new AEAD2022Encryptor(v.Method, v.Key, () => clock.Now, random.Fill)
            {
                AddrBufLength = Address.Length
            };
        }

        private static void PrimeTcpRequest(AEAD2022Encryptor client)
        {
            client.Encrypt(RequestInput, RequestInput.Length, new byte[4096], out _);
        }

        private static void PrimeUdpRequest(AEAD2022Encryptor client)
        {
            client.EncryptUDP(RequestInput, RequestInput.Length, new byte[4096], out _);
        }

        private static byte[] BuildTcpServerResponse(Vector v, long timestamp, byte[][] chunks,
            byte headerType, byte[] requestSaltOverride)
        {
            if (chunks == null || chunks.Length == 0) throw new ArgumentException(nameof(chunks));
            byte[] psk = Convert.FromBase64String(v.Key);
            int keyLen = psk.Length;
            byte[] requestSalt = requestSaltOverride ?? Enumerable.Range(0, keyLen).Select(i => (byte)i).ToArray();
            byte[] responseSalt = Enumerable.Range(0, keyLen).Select(i => (byte)(0x80 + i)).ToArray();
            byte[] subkey = new byte[keyLen];
            Blake3.DeriveSessionSubkey(psk, responseSalt, subkey);
            string cipherName = IsChaCha(v) ? "chacha20-poly1305" : keyLen == 16 ? "aes-128-gcm" : "aes-256-gcm";
            byte[] nonce = new byte[AeadCipher.NonceSize];

            using (var cipher = new AeadCipher(cipherName, subkey, true))
            using (var stream = new MemoryStream())
            {
                stream.Write(responseSalt, 0, responseSalt.Length);
                byte[] header = new byte[1 + 8 + keyLen + 2];
                header[0] = headerType;
                WriteUInt64BE(header, 1, (ulong)timestamp);
                Buffer.BlockCopy(requestSalt, 0, header, 9, keyLen);
                WriteUInt16BE(header, 9 + keyLen, chunks[0].Length);
                WriteSealed(stream, cipher, nonce, header);
                WriteSealed(stream, cipher, nonce, chunks[0]);

                for (int i = 1; i < chunks.Length; i++)
                {
                    byte[] len = new byte[2];
                    WriteUInt16BE(len, 0, chunks[i].Length);
                    WriteSealed(stream, cipher, nonce, len);
                    WriteSealed(stream, cipher, nonce, chunks[i]);
                }
                return stream.ToArray();
            }
        }

        private static void WriteSealed(Stream stream, AeadCipher cipher, byte[] nonce, byte[] plain)
        {
            byte[] sealedBytes = new byte[plain.Length + AeadCipher.TagSize];
            cipher.Seal(nonce, plain, plain.Length, sealedBytes, 0);
            stream.Write(sealedBytes, 0, sealedBytes.Length);
            IncrementNonce(nonce);
        }

        private static byte[] BuildUdpServerPacket(Vector v, long timestamp, byte sessionSeed,
            ulong packetId, byte[] payload, int declaredPaddingLength, bool badEcho,
            int? actualPaddingLength = null)
        {
            byte[] psk = Convert.FromBase64String(v.Key);
            byte[] serverSession = Enumerable.Range(0, 8).Select(i => (byte)(sessionSeed + i)).ToArray();
            byte[] echo = (byte[])ClientSessionId.Clone();
            if (badEcho) echo[0] ^= 1;
            int actualPadding = actualPaddingLength ?? declaredPaddingLength;

            int mainHeaderLength = 1 + 8 + 8 + 2;
            byte[] main = new byte[mainHeaderLength + actualPadding + payload.Length];
            main[0] = 1;
            WriteUInt64BE(main, 1, (ulong)timestamp);
            Buffer.BlockCopy(echo, 0, main, 9, 8);
            WriteUInt16BE(main, 17, declaredPaddingLength);
            for (int i = 0; i < actualPadding; i++) main[mainHeaderLength + i] = (byte)(0xe0 + i);
            Buffer.BlockCopy(payload, 0, main, mainHeaderLength + actualPadding, payload.Length);

            if (IsAes(v))
            {
                byte[] separate = new byte[16];
                Buffer.BlockCopy(serverSession, 0, separate, 0, 8);
                WriteUInt64BE(separate, 8, packetId);
                byte[] encryptedSeparate = new byte[16];
                using (Aes aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.None;
                    aes.Key = psk;
                    using (ICryptoTransform enc = aes.CreateEncryptor())
                    {
                        enc.TransformBlock(separate, 0, 16, encryptedSeparate, 0);
                    }
                }

                byte[] nonce = separate.Skip(4).Take(12).ToArray();
                byte[] subkey = new byte[psk.Length];
                Blake3.DeriveSessionSubkey(psk, serverSession, subkey);
                string cipherName = psk.Length == 16 ? "aes-128-gcm" : "aes-256-gcm";
                byte[] sealedBody = new byte[main.Length + AeadCipher.TagSize];
                using (var cipher = new AeadCipher(cipherName, subkey, true))
                {
                    cipher.Seal(nonce, main, main.Length, sealedBody, 0);
                }
                return encryptedSeparate.Concat(sealedBody).ToArray();
            }
            else
            {
                byte[] body = new byte[16 + main.Length];
                Buffer.BlockCopy(serverSession, 0, body, 0, 8);
                WriteUInt64BE(body, 8, packetId);
                Buffer.BlockCopy(main, 0, body, 16, main.Length);
                byte[] nonce = Enumerable.Range(0, 24).Select(i => (byte)(0xc0 + i)).ToArray();
                byte[] sealedBody = new byte[body.Length + 16];
                ulong sealedLength = 0;
                int ret = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                    sealedBody, ref sealedLength, body, (ulong)body.Length,
                    null, 0, null, nonce, psk);
                Assert.AreEqual(0, ret);
                return nonce.Concat(sealedBody.Take((int)sealedLength)).ToArray();
            }
        }

        private static bool IsAes(Vector v) => !IsChaCha(v);
        private static bool IsChaCha(Vector v) => v.Method.Contains("chacha");
        private static int KeyLength(Vector v) => Convert.FromBase64String(v.Key).Length;

        private static void IncrementNonce(byte[] nonce)
        {
            for (int i = 0; i < nonce.Length; i++)
            {
                if (++nonce[i] != 0) break;
            }
        }

        private static void WriteUInt16BE(byte[] buffer, int offset, int value)
        {
            buffer[offset] = (byte)(value >> 8);
            buffer[offset + 1] = (byte)value;
        }

        private static void WriteUInt64BE(byte[] buffer, int offset, ulong value)
        {
            for (int i = 7; i >= 0; i--)
            {
                buffer[offset + i] = (byte)value;
                value >>= 8;
            }
        }

        private static byte[] Hex(string value)
        {
            byte[] result = new byte[value.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(value.Substring(i * 2, 2), 16);
            }
            return result;
        }
    }
}
