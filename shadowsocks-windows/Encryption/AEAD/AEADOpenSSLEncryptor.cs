using System;
using System.Collections.Generic;
using Shadowsocks.Encryption.Exception;

namespace Shadowsocks.Encryption.AEAD
{
    public class AEADOpenSSLEncryptor
        : AEADEncryptor, IDisposable
    {
        private const int CIPHER_AES = 1;
        private const int CIPHER_CHACHA20IETFPOLY1305 = 2;

        private readonly byte[] _opensslEncSubkey;
        private readonly byte[] _opensslDecSubkey;

        private IntPtr _encryptCtx = IntPtr.Zero;
        private IntPtr _decryptCtx = IntPtr.Zero;

        public AEADOpenSSLEncryptor(string method, string password)
            : base(method, password)
        {
            _opensslEncSubkey = new byte[keyLen];
            _opensslDecSubkey = new byte[keyLen];
        }

        private static readonly Dictionary<string, EncryptorInfo> _ciphers = new Dictionary<string, EncryptorInfo>
        {
            {"aes-128-gcm", new EncryptorInfo("aes-128-gcm", 16, 16, 12, 16, CIPHER_AES)},
            {"aes-192-gcm", new EncryptorInfo("aes-192-gcm", 24, 24, 12, 16, CIPHER_AES)},
            {"aes-256-gcm", new EncryptorInfo("aes-256-gcm", 32, 32, 12, 16, CIPHER_AES)},
            {"chacha20-ietf-poly1305", new EncryptorInfo("chacha20-poly1305", 32, 32, 12, 16, CIPHER_CHACHA20IETFPOLY1305)}
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
            object ctxLock = isEncrypt ? _encryptCtxLock : _decryptCtxLock;
            lock (ctxLock)
            {
                ThrowIfDisposed();
                base.InitCipher(salt, isEncrypt, isUdp);

                byte[] subkey = isEncrypt ? _opensslEncSubkey : _opensslDecSubkey;
                DeriveSessionKey(isEncrypt ? _encryptSalt : _decryptSalt, _masterKey, subkey, isEncrypt);

                EnsureContext(isEncrypt, subkey);
            }
        }

        private IntPtr EnsureContext(bool isEncrypt, byte[] key)
        {
            IntPtr ctx = isEncrypt ? _encryptCtx : _decryptCtx;
            if (ctx != IntPtr.Zero)
            {
                if (OpenSSL.AeadContextSetKey(ctx, key, isEncrypt) != 0)
                {
                    throw new System.Exception("openssl: cannot set key");
                }
                return ctx;
            }

            ctx = OpenSSL.AeadContextNew(_innerLibName, key, nonceLen, isEncrypt);
            if (ctx == IntPtr.Zero)
            {
                throw new System.Exception("openssl: fail to create cipher context");
            }

            if (isEncrypt)
            {
                _encryptCtx = ctx;
            }
            else
            {
                _decryptCtx = ctx;
            }
            return ctx;
        }

        protected override int CipherEncrypt(byte[] plaintext, int plainOffset, int plainLen,
            byte[] ciphertext, int cipherOffset)
        {
            if (plainOffset < 0 || plainLen < 0 || plainOffset > plaintext.Length - plainLen)
                throw new ArgumentOutOfRangeException(nameof(plainOffset));
            if (cipherOffset < 0 || cipherOffset > ciphertext.Length - plainLen - tagLen)
                throw new ArgumentOutOfRangeException(nameof(cipherOffset));

            lock (_encryptCtxLock)
            {
                ThrowIfDisposed();
                int written = OpenSSL.AeadEncrypt(_encryptCtx, _encNonce,
                    plaintext, plainOffset, plainLen, ciphertext, cipherOffset, tagLen);
                if (written != plainLen + tagLen)
                {
                    throw new CryptoErrorException("openssl: fail to encrypt AEAD");
                }
                return written;
            }
        }

        protected override int CipherDecrypt(byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plainOffset)
        {
            int payloadLen = cipherLen - tagLen;
            if (cipherLen < tagLen || cipherOffset < 0 || cipherOffset > ciphertext.Length - cipherLen)
                throw new ArgumentOutOfRangeException(nameof(cipherOffset));
            if (plainOffset < 0 || plainOffset > plaintext.Length - payloadLen)
                throw new ArgumentOutOfRangeException(nameof(plainOffset));

            lock (_decryptCtxLock)
            {
                ThrowIfDisposed();
                int written = OpenSSL.AeadDecrypt(_decryptCtx, _decNonce,
                    ciphertext, cipherOffset, cipherLen, plaintext, plainOffset, tagLen);
                if (written < 0)
                {
                    throw new CryptoErrorException(written == -2
                        ? "openssl: authentication failed"
                        : "openssl: fail to decrypt AEAD");
                }
                return written;
            }
        }

        #region IDisposable

        private bool _disposed;
        private readonly object _encryptCtxLock = new object();
        private readonly object _decryptCtxLock = new object();

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new CryptoErrorException("openssl: the encryptor has been disposed");
            }
        }

        public override void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~AEADOpenSSLEncryptor()
        {
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            // Operations take only their direction's lock so upload and download
            // can run concurrently. Disposal takes both in a fixed order before
            // freeing either native context.
            lock (_encryptCtxLock)
            {
                lock (_decryptCtxLock)
                {
                    if (_disposed) return;
                    _disposed = true;

                    DisposeHkdfContexts();
                    if (_encryptCtx != IntPtr.Zero)
                    {
                        OpenSSL.AeadContextFree(_encryptCtx);
                        _encryptCtx = IntPtr.Zero;
                    }
                    if (_decryptCtx != IntPtr.Zero)
                    {
                        OpenSSL.AeadContextFree(_decryptCtx);
                        _decryptCtx = IntPtr.Zero;
                    }
                }
            }
        }

        #endregion
    }
}
