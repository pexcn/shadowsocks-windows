using System;
using System.Runtime.InteropServices;
using System.Security;

namespace Shadowsocks.Encryption
{
    // XXX: only for OpenSSL 1.1.0 and higher
    public static class OpenSSL
    {
        private const string DLLNAME = LibSsCrypto.DLLNAME;

        static OpenSSL()
        {
            LibSsCrypto.EnsureLoaded();
        }

        public static IntPtr AeadContextNew(string cipherName, byte[] key,
            int nonceLength, bool isEncrypt)
        {
            return sscrypto_aead_ctx_new(cipherName, key, key.Length, nonceLength,
                isEncrypt ? 1 : 0);
        }

        public static int AeadContextSetKey(IntPtr ctx, byte[] key, bool isEncrypt)
        {
            return sscrypto_aead_ctx_set_key(ctx, key, isEncrypt ? 1 : 0);
        }

        public static void AeadContextFree(IntPtr ctx)
        {
            sscrypto_aead_ctx_free(ctx);
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
        private static extern IntPtr sscrypto_aead_ctx_new(
            [MarshalAs(UnmanagedType.LPStr)] string cipherName,
            byte[] key, int keyLength, int nonceLength, int isEncrypt);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sscrypto_aead_ctx_set_key(
            IntPtr ctx, byte[] key, int isEncrypt);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void sscrypto_aead_ctx_free(IntPtr ctx);
    }
}