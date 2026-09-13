using System;
using Shadowsocks.Encryption.Exception;

namespace Shadowsocks.Encryption.AEAD
{
    /// <summary>
    /// One direction of an AEAD cipher over an OpenSSL EVP context.
    /// The key schedule is set up once; Seal and Open only rebind the nonce.
    /// </summary>
    internal sealed class AeadCipher : IDisposable
    {
        public const int TagSize = 16;
        public const int NonceSize = 12;

        private readonly bool _isEncrypt;
        private IntPtr _ctx;

        public AeadCipher(string cipherName, byte[] key, bool isEncrypt)
        {
            _isEncrypt = isEncrypt;
            int direction = isEncrypt ? OpenSSL.OPENSSL_ENCRYPT : OpenSSL.OPENSSL_DECRYPT;

            IntPtr cipherInfo = OpenSSL.GetCipherInfo(cipherName);
            if (cipherInfo == IntPtr.Zero)
            {
                throw new System.Exception($"openssl: cipher {cipherName} not found");
            }

            _ctx = OpenSSL.EVP_CIPHER_CTX_new();
            if (_ctx == IntPtr.Zero)
            {
                throw new System.Exception("openssl: fail to create ctx");
            }

            try
            {
                if (OpenSSL.EVP_CipherInit_ex(_ctx, cipherInfo, IntPtr.Zero, null, null, direction) != 1)
                {
                    throw new System.Exception("openssl: fail to init ctx");
                }
                if (OpenSSL.EVP_CIPHER_CTX_set_key_length(_ctx, key.Length) != 1)
                {
                    throw new System.Exception("openssl: fail to set key length");
                }
                if (OpenSSL.EVP_CIPHER_CTX_ctrl(_ctx, OpenSSL.EVP_CTRL_AEAD_SET_IVLEN,
                        NonceSize, IntPtr.Zero) != 1)
                {
                    throw new System.Exception("openssl: fail to set AEAD nonce length");
                }
                if (OpenSSL.EVP_CipherInit_ex(_ctx, IntPtr.Zero, IntPtr.Zero, key, null, direction) != 1)
                {
                    throw new System.Exception("openssl: cannot set key");
                }
                if (OpenSSL.EVP_CIPHER_CTX_set_padding(_ctx, 0) != 1)
                {
                    throw new System.Exception("openssl: cannot disable padding");
                }
            }
            catch
            {
                OpenSSL.EVP_CIPHER_CTX_free(_ctx);
                _ctx = IntPtr.Zero;
                throw;
            }
        }

        public void Seal(byte[] nonce, byte[] plaintext, int plainLen, byte[] outbuf, int outOffset)
        {
            Seal(nonce, plaintext, 0, plainLen, outbuf, outOffset);
        }

        /// <summary>
        /// Seals directly into the caller's final output buffer. No temporary
        /// ciphertext or tag arrays are created on the chunk hot path.
        /// </summary>
        public void Seal(byte[] nonce, byte[] plaintext, int plainOffset, int plainLen,
            byte[] outbuf, int outOffset)
        {
            ThrowIfDisposed();
            if (plainOffset < 0 || plainLen < 0 || plainOffset > plaintext.Length - plainLen)
                throw new ArgumentOutOfRangeException(nameof(plainOffset));
            if (outOffset < 0 || outOffset > outbuf.Length - plainLen - TagSize)
                throw new ArgumentOutOfRangeException(nameof(outOffset));

            OpenSSL.SetCtxNonce(_ctx, nonce, _isEncrypt);

            int written;
            if (OpenSSL.CipherUpdate(_ctx, outbuf, outOffset, out written,
                    plaintext, plainOffset, plainLen) != 1)
            {
                throw new CryptoErrorException("openssl: fail to encrypt AEAD");
            }

            int finalLen = 0;
            if (OpenSSL.CipherFinal(_ctx, outbuf, outOffset + written, ref finalLen) != 1 || finalLen != 0)
            {
                throw new CryptoErrorException("openssl: fail to finalize AEAD");
            }

            OpenSSL.AEADGetTag(_ctx, outbuf, outOffset + written, TagSize);
        }

        public int Open(byte[] nonce, byte[] ciphertext, int cipherLen, byte[] outbuf, int outOffset)
        {
            return Open(nonce, ciphertext, 0, cipherLen, outbuf, outOffset);
        }

        /// <summary>
        /// Opens ciphertext||tag from an arbitrary input offset and writes the
        /// plaintext directly to the final output buffer.
        /// </summary>
        public int Open(byte[] nonce, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] outbuf, int outOffset)
        {
            ThrowIfDisposed();
            int plainLen = cipherLen - TagSize;
            if (plainLen < 0)
            {
                throw new CryptoErrorException("aead: ciphertext is shorter than its tag");
            }
            if (cipherOffset < 0 || cipherOffset > ciphertext.Length - cipherLen)
                throw new ArgumentOutOfRangeException(nameof(cipherOffset));
            if (outOffset < 0 || outOffset > outbuf.Length - plainLen)
                throw new ArgumentOutOfRangeException(nameof(outOffset));

            OpenSSL.SetCtxNonce(_ctx, nonce, _isEncrypt);
            OpenSSL.AEADSetTag(_ctx, ciphertext, cipherOffset + plainLen, TagSize);

            int written;
            if (OpenSSL.CipherUpdate(_ctx, outbuf, outOffset, out written,
                    ciphertext, cipherOffset, plainLen) != 1)
            {
                throw new CryptoErrorException("openssl: fail to decrypt AEAD");
            }

            int finalLen = 0;
            if (OpenSSL.CipherFinal(_ctx, outbuf, outOffset + written, ref finalLen) <= 0)
            {
                throw new CryptoErrorException("aead: authentication failed");
            }

            if (finalLen != 0)
            {
                throw new CryptoErrorException("openssl: unexpected AEAD final output");
            }
            return written;
        }

        private readonly object _disposeLock = new object();

        private void ThrowIfDisposed()
        {
            if (_ctx == IntPtr.Zero)
            {
                throw new ObjectDisposedException(nameof(AeadCipher));
            }
        }

        public void Dispose()
        {
            lock (_disposeLock)
            {
                if (_ctx != IntPtr.Zero)
                {
                    OpenSSL.EVP_CIPHER_CTX_free(_ctx);
                    _ctx = IntPtr.Zero;
                }
            }
            GC.SuppressFinalize(this);
        }

        ~AeadCipher()
        {
            Dispose();
        }
    }
}
