using System;
using System.Runtime.InteropServices;

namespace Shadowsocks.Encryption
{
    public static class MbedTLS
    {
        private const string DLLNAME = LibSsCrypto.DLLNAME;

        static MbedTLS()
        {
            LibSsCrypto.EnsureLoaded();
        }

        public static byte[] MD5(byte[] input)
        {
            byte[] output = new byte[16];
            if (md5_ret(input, (UIntPtr)(uint) input.Length, output) != 0)
                throw new System.Exception("mbedtls: MD5 failure");
            return output;
        }

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int md5_ret(byte[] input, UIntPtr ilen, byte[] output);

        // Not mbedtls_hkdf: libsscrypto exports its own SHA1-fixed wrapper under
        // this name, and that one takes int lengths, so they stay int on x64.
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int hkdf(byte[] salt,
            int salt_len, byte[] ikm, int ikm_len,
            byte[] info, int info_len, byte[] okm,
            int okm_len);
    }
}
