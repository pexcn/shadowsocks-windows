using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Shadowsocks.Encryption
{
    // XXX: only for OpenSSL 1.1.0 and higher
    public static class OpenSSL
    {
        private const string DLLNAME = LibSsCrypto.DLLNAME;

        public const int OPENSSL_ENCRYPT = 1;
        public const int OPENSSL_DECRYPT = 0;

        public const int EVP_CTRL_AEAD_SET_IVLEN = 0x9;

        static OpenSSL()
        {
            LibSsCrypto.EnsureLoaded();
        }

        public static IntPtr GetCipherInfo(string cipherName)
        {
            var name = Encoding.ASCII.GetBytes(cipherName);
            Array.Resize(ref name, name.Length + 1);
            return EVP_get_cipherbyname(name);
        }

        public static unsafe int AeadEncrypt(IntPtr ctx, byte[] nonce,
            byte[] input, int inputOffset, int inputLength,
            byte[] output, int outputOffset, int tagLength)
        {
            if (nonce == null) throw new ArgumentNullException(nameof(nonce));
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (inputLength < 0 || inputOffset < 0 || inputOffset > input.Length - inputLength)
                throw new ArgumentOutOfRangeException(nameof(inputOffset));
            if (outputOffset < 0 || outputOffset > output.Length - inputLength - tagLength)
                throw new ArgumentOutOfRangeException(nameof(outputOffset));

            fixed (byte* nonceBase = nonce)
            fixed (byte* inputBase = input)
            fixed (byte* outputBase = output)
            {
                return sscrypto_aead_encrypt(ctx, (IntPtr)nonceBase,
                    (IntPtr)(inputBase + inputOffset), inputLength,
                    (IntPtr)(outputBase + outputOffset), tagLength);
            }
        }

        public static unsafe int AeadDecrypt(IntPtr ctx, byte[] nonce,
            byte[] input, int inputOffset, int inputLength,
            byte[] output, int outputOffset, int tagLength)
        {
            int plainLength = inputLength - tagLength;
            if (nonce == null) throw new ArgumentNullException(nameof(nonce));
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (plainLength < 0 || inputOffset < 0 || inputOffset > input.Length - inputLength)
                throw new ArgumentOutOfRangeException(nameof(inputOffset));
            if (outputOffset < 0 || outputOffset > output.Length - plainLength)
                throw new ArgumentOutOfRangeException(nameof(outputOffset));

            fixed (byte* nonceBase = nonce)
            fixed (byte* inputBase = input)
            fixed (byte* outputBase = output)
            {
                return sscrypto_aead_decrypt(ctx, (IntPtr)nonceBase,
                    (IntPtr)(inputBase + inputOffset), inputLength,
                    (IntPtr)(outputBase + outputOffset), tagLength);
            }
        }

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sscrypto_aead_encrypt(IntPtr ctx, IntPtr nonce,
            IntPtr input, int inputLength, IntPtr output, int tagLength);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sscrypto_aead_decrypt(IntPtr ctx, IntPtr nonce,
            IntPtr input, int inputLength, IntPtr output, int tagLength);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr EVP_CIPHER_CTX_new();

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void EVP_CIPHER_CTX_free(IntPtr ctx);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int EVP_CipherInit_ex(IntPtr ctx, IntPtr type,
            IntPtr impl, byte[] key, byte[] iv, int enc);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int EVP_CIPHER_CTX_set_padding(IntPtr x, int padding);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int EVP_CIPHER_CTX_set_key_length(IntPtr x, int keylen);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int EVP_CIPHER_CTX_ctrl(IntPtr ctx, int type, int arg, IntPtr ptr);

        /// <summary>
        /// simulate NUL-terminated string
        /// </summary>
        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr EVP_get_cipherbyname(byte[] name);
    }
}