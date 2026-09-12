using System;
using System.Runtime.InteropServices;

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
                    else /* 1 means already initialized; 0 means success */
                    {
                        _initialized = true;
                    }
                }
            }
        }

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sodium_init();

        #region AEAD

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int sodium_increment(byte[] n, UIntPtr nlen);

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

        #endregion
    }
}
