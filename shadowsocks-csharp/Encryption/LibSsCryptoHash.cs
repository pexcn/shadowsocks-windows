using System;
using System.Runtime.InteropServices;
using System.Security;

namespace Shadowsocks.Encryption
{
    public static class LibSsCryptoHash
    {
        private const string DLLNAME = LibSsCrypto.DLLNAME;

        static LibSsCryptoHash()
        {
            LibSsCrypto.EnsureLoaded();
        }

        public static byte[] MD5(byte[] input)
        {
            byte[] output = new byte[16];
            if (md5_ret(input, (UIntPtr)(uint) input.Length, output) != 0)
                throw new System.Exception("libsscrypto: MD5 failure");
            return output;
        }

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int md5_ret(byte[] input, UIntPtr ilen, byte[] output);

        // libsscrypto exports its own SHA1-fixed wrapper under this name, and
        // that one takes int lengths, so they stay int on x64.
        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int hkdf(byte[] salt,
            int salt_len, byte[] ikm, int ikm_len,
            byte[] info, int info_len, byte[] okm,
            int okm_len);
    }
}
