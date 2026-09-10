using System;
using Shadowsocks.Encryption.Exception;

namespace Shadowsocks.Encryption.AEAD
{
    /// <summary>
    /// One direction of an AEAD cipher over an OpenSSL EVP context.
    ///
    /// The key schedule is set up once in the constructor; Seal and Open only
    /// rebind the nonce. Handing the key to EVP_CipherInit_ex again per chunk,
    /// which is what the AEAD-2018 path does, recomputes the AES key schedule
    /// every time.
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

            if (OpenSSL.EVP_CipherInit_ex(_ctx, cipherInfo, IntPtr.Zero, null, null, direction) != 1)
            {
                throw new System.Exception("openssl: fail to init ctx");
            }
            if (OpenSSL.EVP_CIPHER_CTX_set_key_length(_ctx, key.Length) != 1)
            {
                throw new System.Exception("openssl: fail to set key length");
            }
            if (OpenSSL.EVP_CIPHER_CTX_ctrl(_ctx, OpenSSL.EVP_CTRL_AEAD_SET_IVLEN, NonceSize, IntPtr.Zero) != 1)
            {
                throw new System.Exception("openssl: fail to set AEAD nonce length");
            }
            if (OpenSSL.EVP_CipherInit_ex(_ctx, IntPtr.Zero, IntPtr.Zero, key, null, direction) != 1)
            {
                throw new System.Exception("openssl: cannot set key");
            }
            OpenSSL.EVP_CIPHER_CTX_set_padding(_ctx, 0);
        }

        /// <summary>
        /// Seals <paramref name="plainLen"/> bytes of <paramref name="plaintext"/> as
        /// ciphertext||tag at <paramref name="outOffset"/>, writing plainLen + TagSize bytes.
        /// </summary>
        public void Seal(byte[] nonce, byte[] plaintext, int plainLen, byte[] outbuf, int outOffset)
        {
            OpenSSL.SetCtxNonce(_ctx, nonce, _isEncrypt);

            // Zero-length arrays would give OpenSSL a pointer it must not read;
            // the length says so too, but there is no reason to rely on that.
            byte[] tmp = new byte[Math.Max(plainLen, 1)];
            int written;
            if (OpenSSL.EVP_CipherUpdate(_ctx, tmp, out written, plaintext, plainLen) != 1)
            {
                throw new CryptoErrorException("openssl: fail to encrypt AEAD");
            }

            int finalLen = 0;
            if (OpenSSL.EVP_CipherFinal_ex(_ctx, tmp, ref finalLen) != 1 || finalLen != 0)
            {
                throw new CryptoErrorException("openssl: fail to finalize AEAD");
            }

            Buffer.BlockCopy(tmp, 0, outbuf, outOffset, written);

            byte[] tag = new byte[TagSize];
            OpenSSL.AEADGetTag(_ctx, tag, TagSize);
            Buffer.BlockCopy(tag, 0, outbuf, outOffset + written, TagSize);
        }

        /// <summary>
        /// Opens ciphertext||tag and writes the plaintext at <paramref name="outOffset"/>.
        /// Returns the plaintext length. Throws if the tag does not verify.
        /// </summary>
        public int Open(byte[] nonce, byte[] ciphertext, int cipherLen, byte[] outbuf, int outOffset)
        {
            int plainLen = cipherLen - TagSize;
            if (plainLen < 0)
            {
                throw new CryptoErrorException("aead: ciphertext is shorter than its tag");
            }

            OpenSSL.SetCtxNonce(_ctx, nonce, _isEncrypt);

            byte[] tag = new byte[TagSize];
            Buffer.BlockCopy(ciphertext, plainLen, tag, 0, TagSize);
            OpenSSL.AEADSetTag(_ctx, tag, TagSize);

            byte[] tmp = new byte[Math.Max(plainLen, 1)];
            int written;
            if (OpenSSL.EVP_CipherUpdate(_ctx, tmp, out written, ciphertext, plainLen) != 1)
            {
                throw new CryptoErrorException("openssl: fail to decrypt AEAD");
            }

            int finalLen = 0;
            if (OpenSSL.EVP_CipherFinal_ex(_ctx, tmp, ref finalLen) <= 0)
            {
                throw new CryptoErrorException("aead: authentication failed");
            }

            Buffer.BlockCopy(tmp, 0, outbuf, outOffset, written);
            return written;
        }

        // The finalizer is the backstop for an encryptor that never gets
        // disposed; it runs on its own thread, so freeing the context has to be
        // exactly once. Same guard as AEADOpenSSLEncryptor's.
        private readonly object _disposeLock = new object();

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
