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

        private IntPtr _ctx;

        public AeadCipher(string cipherName, byte[] key, bool isEncrypt)
        {
            _ctx = OpenSSL.AeadContextNew(cipherName, key, NonceSize, isEncrypt);
            if (_ctx == IntPtr.Zero)
            {
                throw new System.Exception($"openssl: fail to create {cipherName} context");
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

            int written = OpenSSL.AeadEncrypt(_ctx, nonce, plaintext, plainOffset, plainLen,
                outbuf, outOffset, TagSize);
            if (written != plainLen + TagSize)
            {
                throw new CryptoErrorException("openssl: fail to encrypt AEAD");
            }
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

            int written = OpenSSL.AeadDecrypt(_ctx, nonce, ciphertext, cipherOffset, cipherLen,
                outbuf, outOffset, TagSize);
            if (written < 0)
            {
                throw new CryptoErrorException(written == -2
                    ? "aead: authentication failed"
                    : "openssl: fail to decrypt AEAD");
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
                    OpenSSL.AeadContextFree(_ctx);
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
