using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using Shadowsocks.Encryption.Exception;

namespace Shadowsocks.Encryption
{
    // XXX: only for OpenSSL 1.1.0 and higher
    public static class OpenSSL
    {
        private const string DLLNAME = LibSsCrypto.DLLNAME;

        public const int OPENSSL_ENCRYPT = 1;
        public const int OPENSSL_DECRYPT = 0;

        public const int EVP_CTRL_AEAD_SET_IVLEN = 0x9;
        public const int EVP_CTRL_AEAD_GET_TAG = 0x10;
        public const int EVP_CTRL_AEAD_SET_TAG = 0x11;

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

        /// <summary>
        /// Need init cipher context after EVP_CipherFinal_ex to reuse context.
        /// </summary>
        public static void SetCtxNonce(IntPtr ctx, byte[] nonce, bool isEncrypt)
        {
            var ret = EVP_CipherInit_ex(ctx, IntPtr.Zero,
                IntPtr.Zero, null,
                nonce,
                isEncrypt ? OPENSSL_ENCRYPT : OPENSSL_DECRYPT);
            if (ret != 1) throw new System.Exception("openssl: fail to set AEAD nonce");
        }

        /// <summary>
        /// Run EVP_CipherUpdate directly between two managed arrays without an
        /// intermediate managed buffer. The arrays stay pinned only for the
        /// duration of the native call.
        /// </summary>
        public static unsafe int CipherUpdate(IntPtr ctx, byte[] output, int outputOffset,
            out int outputLength, byte[] input, int inputOffset, int inputLength)
        {
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (inputLength < 0)
                throw new ArgumentOutOfRangeException(nameof(inputLength));
            if (outputOffset < 0 || outputOffset > output.Length - inputLength)
                throw new ArgumentOutOfRangeException(nameof(outputOffset));
            if (inputOffset < 0 || inputOffset > input.Length - inputLength)
                throw new ArgumentOutOfRangeException(nameof(inputOffset));

            fixed (byte* outputBase = output)
            fixed (byte* inputBase = input)
            {
                return EVP_CipherUpdatePtr(ctx,
                    (IntPtr)(outputBase + outputOffset), out outputLength,
                    (IntPtr)(inputBase + inputOffset), inputLength);
            }
        }

        public static unsafe int CipherFinal(IntPtr ctx, byte[] output, int outputOffset,
            ref int outputLength)
        {
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (outputOffset < 0 || outputOffset > output.Length)
                throw new ArgumentOutOfRangeException(nameof(outputOffset));

            fixed (byte* outputBase = output)
            {
                return EVP_CipherFinalPtr(ctx, (IntPtr)(outputBase + outputOffset), ref outputLength);
            }
        }

        public static unsafe void AEADGetTag(IntPtr ctx, byte[] buffer, int offset, int taglen)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || taglen < 0 || offset > buffer.Length - taglen)
                throw new ArgumentOutOfRangeException(nameof(offset));

            fixed (byte* basePtr = buffer)
            {
                var ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen,
                    (IntPtr)(basePtr + offset));
                if (ret != 1) throw new CryptoErrorException("openssl: fail to get AEAD tag");
            }
        }

        public static void AEADGetTag(IntPtr ctx, byte[] tagbuf, int taglen)
        {
            AEADGetTag(ctx, tagbuf, 0, taglen);
        }

        public static unsafe void AEADSetTag(IntPtr ctx, byte[] buffer, int offset, int taglen)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || taglen < 0 || offset > buffer.Length - taglen)
                throw new ArgumentOutOfRangeException(nameof(offset));

            fixed (byte* basePtr = buffer)
            {
                var ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen,
                    (IntPtr)(basePtr + offset));
                if (ret != 1) throw new CryptoErrorException("openssl: fail to set AEAD tag");
            }
        }

        public static void AEADSetTag(IntPtr ctx, byte[] tagbuf, int taglen)
        {
            AEADSetTag(ctx, tagbuf, 0, taglen);
        }

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
        public static extern int EVP_CipherUpdate(IntPtr ctx, byte[] outb,
            out int outl, byte[] inb, int inl);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_CipherUpdate")]
        private static extern int EVP_CipherUpdatePtr(IntPtr ctx, IntPtr outb,
            out int outl, IntPtr inb, int inl);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int EVP_CipherFinal_ex(IntPtr ctx, byte[] outm, ref int outl);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_CipherFinal_ex")]
        private static extern int EVP_CipherFinalPtr(IntPtr ctx, IntPtr outm, ref int outl);

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