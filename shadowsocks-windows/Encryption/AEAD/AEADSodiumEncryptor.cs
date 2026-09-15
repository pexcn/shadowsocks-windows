using System;
using System.Collections.Generic;
using System.Diagnostics;
using Shadowsocks.Encryption.Exception;

namespace Shadowsocks.Encryption.AEAD
{
    public class AEADSodiumEncryptor
        : AEADEncryptor, IDisposable
    {
        private const int CIPHER_CHACHA20IETFPOLY1305 = 1;
        private const int CIPHER_XCHACHA20IETFPOLY1305 = 2;

        private readonly byte[] _sodiumEncSubkey;
        private readonly byte[] _sodiumDecSubkey;

        public AEADSodiumEncryptor(string method, string password)
            : base(method, password)
        {
            _sodiumEncSubkey = new byte[keyLen];
            _sodiumDecSubkey = new byte[keyLen];
        }

        private static readonly Dictionary<string, EncryptorInfo> _ciphers = new Dictionary<string, EncryptorInfo>
        {
            {"chacha20-ietf-poly1305", new EncryptorInfo(32, 32, 12, 16, CIPHER_CHACHA20IETFPOLY1305)},
            {"xchacha20-ietf-poly1305", new EncryptorInfo(32, 32, 24, 16, CIPHER_XCHACHA20IETFPOLY1305)},
        };

        public static List<string> SupportedCiphers()
        {
            return new List<string>(_ciphers.Keys);
        }

        protected override Dictionary<string, EncryptorInfo> getCiphers()
        {
            return _ciphers;
        }

        public override void InitCipher(byte[] salt, bool isEncrypt, bool isUdp)
        {
            base.InitCipher(salt, isEncrypt, isUdp);
            DeriveSessionKey(isEncrypt ? _encryptSalt : _decryptSalt, _masterKey,
                isEncrypt ? _sodiumEncSubkey : _sodiumDecSubkey, isEncrypt);
        }

        protected override int CipherEncrypt(byte[] plaintext, int plainOffset, int plainLen,
            byte[] ciphertext, int cipherOffset)
        {
            if (plainOffset < 0 || plainLen < 0 || plainOffset > plaintext.Length - plainLen)
                throw new ArgumentOutOfRangeException(nameof(plainOffset));
            if (cipherOffset < 0 || cipherOffset > ciphertext.Length - plainLen - tagLen)
                throw new ArgumentOutOfRangeException(nameof(cipherOffset));
            Debug.Assert(_sodiumEncSubkey != null);
            ulong encLen = 0;
            int ret;
            switch (_cipher)
            {
                case CIPHER_CHACHA20IETFPOLY1305:
                    ret = Sodium.ChaCha20Poly1305IetfEncrypt(ciphertext, cipherOffset, ref encLen,
                        plaintext, plainOffset, (ulong)plainLen, _encNonce, 0, _sodiumEncSubkey);
                    break;
                case CIPHER_XCHACHA20IETFPOLY1305:
                    ret = Sodium.XChaCha20Poly1305IetfEncrypt(ciphertext, cipherOffset, ref encLen,
                        plaintext, plainOffset, (ulong)plainLen, _encNonce, 0, _sodiumEncSubkey);
                    break;
                default:
                    throw new System.Exception("not implemented");
            }
            if (ret != 0) throw new CryptoErrorException($"ret is {ret}");
            return checked((int)encLen);
        }

        protected override int CipherDecrypt(byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plainOffset)
        {
            int expectedPlainLen = cipherLen - tagLen;
            if (cipherLen < tagLen || cipherOffset < 0 || cipherOffset > ciphertext.Length - cipherLen)
                throw new ArgumentOutOfRangeException(nameof(cipherOffset));
            if (plainOffset < 0 || plainOffset > plaintext.Length - expectedPlainLen)
                throw new ArgumentOutOfRangeException(nameof(plainOffset));
            Debug.Assert(_sodiumDecSubkey != null);
            ulong plainLen = 0;
            int ret;
            switch (_cipher)
            {
                case CIPHER_CHACHA20IETFPOLY1305:
                    ret = Sodium.ChaCha20Poly1305IetfDecrypt(plaintext, plainOffset, ref plainLen,
                        ciphertext, cipherOffset, (ulong)cipherLen, _decNonce, 0, _sodiumDecSubkey);
                    break;
                case CIPHER_XCHACHA20IETFPOLY1305:
                    ret = Sodium.XChaCha20Poly1305IetfDecrypt(plaintext, plainOffset, ref plainLen,
                        ciphertext, cipherOffset, (ulong)cipherLen, _decNonce, 0, _sodiumDecSubkey);
                    break;
                default:
                    throw new System.Exception("not implemented");
            }
            if (ret != 0) throw new CryptoErrorException($"ret is {ret}");
            return checked((int)plainLen);
        }

        public override void Dispose()
        {
            DisposeHkdfContexts();
        }
    }
}