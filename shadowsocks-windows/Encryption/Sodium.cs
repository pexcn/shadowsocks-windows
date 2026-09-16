using System;
using System.Runtime.InteropServices;
using System.Security;

namespace Shadowsocks.Encryption
{
    public static class Sodium
    {
        private const string DLLNAME = LibSsCrypto.DLLNAME;

        private static bool _initialized = false;
        private static readonly object _initLock = new object();

        static Sodium()
        {
            LibSsCrypto.EnsureLoaded();

            lock (_initLock)
            {
                if (!_initialized)
                {
                    if (sodium_init() == -1)
                    {
                        throw new System.Exception("Failed to initialize sodium");
                    }
                    _initialized = true;
                }
            }
        }

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sodium_init();

        #region AEAD

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_chacha20poly1305_ietf_encrypt(byte[] c, ref ulong clen_p, byte[] m,
            ulong mlen, byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[] k);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_chacha20poly1305_ietf_decrypt(byte[] m, ref ulong mlen_p,
            byte[] nsec, byte[] c, ulong clen, byte[] ad, ulong adlen, byte[] npub, byte[] k);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_xchacha20poly1305_ietf_encrypt(byte[] c, ref ulong clen_p, byte[] m, ulong mlen,
            byte[] ad, ulong adlen, byte[] nsec, byte[] npub, byte[] k);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_xchacha20poly1305_ietf_decrypt(byte[] m, ref ulong mlen_p, byte[] nsec, byte[] c,
            ulong clen, byte[] ad, ulong adlen, byte[] npub, byte[] k);

        private const int AeadTagSize = 16;

        internal static unsafe int ChaCha20Poly1305IetfEncrypt(byte[] output, int outputOffset,
            ref ulong outputLength, byte[] input, int inputOffset, ulong inputLength,
            byte[] nonce, int nonceOffset, byte[] key)
        {
            ValidateSlices(output, outputOffset, EncryptOutputLength(inputLength),
                input, inputOffset, inputLength, nonce, nonceOffset, 12, key);
            fixed (byte* outputBase = output)
            fixed (byte* inputBase = input)
            fixed (byte* nonceBase = nonce)
            fixed (byte* keyBase = key)
            {
                return crypto_aead_chacha20poly1305_ietf_encrypt_ptr(
                    (IntPtr)(outputBase + outputOffset), ref outputLength,
                    (IntPtr)(inputBase + inputOffset), inputLength,
                    IntPtr.Zero, 0, IntPtr.Zero,
                    (IntPtr)(nonceBase + nonceOffset), (IntPtr)keyBase);
            }
        }

        internal static unsafe int ChaCha20Poly1305IetfDecrypt(byte[] output, int outputOffset,
            ref ulong outputLength, byte[] input, int inputOffset, ulong inputLength,
            byte[] nonce, int nonceOffset, byte[] key)
        {
            ValidateSlices(output, outputOffset, DecryptOutputLength(inputLength),
                input, inputOffset, inputLength, nonce, nonceOffset, 12, key);
            fixed (byte* outputBase = output)
            fixed (byte* inputBase = input)
            fixed (byte* nonceBase = nonce)
            fixed (byte* keyBase = key)
            {
                return crypto_aead_chacha20poly1305_ietf_decrypt_ptr(
                    (IntPtr)(outputBase + outputOffset), ref outputLength, IntPtr.Zero,
                    (IntPtr)(inputBase + inputOffset), inputLength,
                    IntPtr.Zero, 0,
                    (IntPtr)(nonceBase + nonceOffset), (IntPtr)keyBase);
            }
        }

        internal static unsafe int XChaCha20Poly1305IetfEncrypt(byte[] output, int outputOffset,
            ref ulong outputLength, byte[] input, int inputOffset, ulong inputLength,
            byte[] nonce, int nonceOffset, byte[] key)
        {
            ValidateSlices(output, outputOffset, EncryptOutputLength(inputLength),
                input, inputOffset, inputLength, nonce, nonceOffset, 24, key);
            fixed (byte* outputBase = output)
            fixed (byte* inputBase = input)
            fixed (byte* nonceBase = nonce)
            fixed (byte* keyBase = key)
            {
                return crypto_aead_xchacha20poly1305_ietf_encrypt_ptr(
                    (IntPtr)(outputBase + outputOffset), ref outputLength,
                    (IntPtr)(inputBase + inputOffset), inputLength,
                    IntPtr.Zero, 0, IntPtr.Zero,
                    (IntPtr)(nonceBase + nonceOffset), (IntPtr)keyBase);
            }
        }

        internal static unsafe int XChaCha20Poly1305IetfDecrypt(byte[] output, int outputOffset,
            ref ulong outputLength, byte[] input, int inputOffset, ulong inputLength,
            byte[] nonce, int nonceOffset, byte[] key)
        {
            ValidateSlices(output, outputOffset, DecryptOutputLength(inputLength),
                input, inputOffset, inputLength, nonce, nonceOffset, 24, key);
            fixed (byte* outputBase = output)
            fixed (byte* inputBase = input)
            fixed (byte* nonceBase = nonce)
            fixed (byte* keyBase = key)
            {
                return crypto_aead_xchacha20poly1305_ietf_decrypt_ptr(
                    (IntPtr)(outputBase + outputOffset), ref outputLength, IntPtr.Zero,
                    (IntPtr)(inputBase + inputOffset), inputLength,
                    IntPtr.Zero, 0,
                    (IntPtr)(nonceBase + nonceOffset), (IntPtr)keyBase);
            }
        }

        private static int EncryptOutputLength(ulong inputLength)
        {
            if (inputLength > int.MaxValue - AeadTagSize)
                throw new ArgumentOutOfRangeException(nameof(inputLength));
            return (int)inputLength + AeadTagSize;
        }

        private static int DecryptOutputLength(ulong inputLength)
        {
            if (inputLength < AeadTagSize || inputLength > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(inputLength));
            return (int)inputLength - AeadTagSize;
        }

        private static void ValidateSlices(byte[] output, int outputOffset, int outputLength,
            byte[] input, int inputOffset, ulong inputLength,
            byte[] nonce, int nonceOffset, int nonceLength, byte[] key)
        {
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (nonce == null) throw new ArgumentNullException(nameof(nonce));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (outputOffset < 0 || outputLength < 0 || outputOffset > output.Length - outputLength)
                throw new ArgumentOutOfRangeException(nameof(outputOffset));
            if (inputLength > int.MaxValue || inputOffset < 0 || inputOffset > input.Length - (int)inputLength)
                throw new ArgumentOutOfRangeException(nameof(inputOffset));
            if (nonceOffset < 0 || nonceOffset > nonce.Length - nonceLength)
                throw new ArgumentOutOfRangeException(nameof(nonceOffset));
        }

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "crypto_aead_chacha20poly1305_ietf_encrypt")]
        private static extern int crypto_aead_chacha20poly1305_ietf_encrypt_ptr(IntPtr c, ref ulong clen_p,
            IntPtr m, ulong mlen, IntPtr ad, ulong adlen, IntPtr nsec, IntPtr npub, IntPtr k);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "crypto_aead_chacha20poly1305_ietf_decrypt")]
        private static extern int crypto_aead_chacha20poly1305_ietf_decrypt_ptr(IntPtr m, ref ulong mlen_p,
            IntPtr nsec, IntPtr c, ulong clen, IntPtr ad, ulong adlen, IntPtr npub, IntPtr k);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "crypto_aead_xchacha20poly1305_ietf_encrypt")]
        private static extern int crypto_aead_xchacha20poly1305_ietf_encrypt_ptr(IntPtr c, ref ulong clen_p,
            IntPtr m, ulong mlen, IntPtr ad, ulong adlen, IntPtr nsec, IntPtr npub, IntPtr k);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "crypto_aead_xchacha20poly1305_ietf_decrypt")]
        private static extern int crypto_aead_xchacha20poly1305_ietf_decrypt_ptr(IntPtr m, ref ulong mlen_p,
            IntPtr nsec, IntPtr c, ulong clen, IntPtr ad, ulong adlen, IntPtr npub, IntPtr k);

        #endregion
    }
}
