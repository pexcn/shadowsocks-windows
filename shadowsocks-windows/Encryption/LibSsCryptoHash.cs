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

        internal sealed class HkdfContext : IDisposable
        {
            private readonly object _sync = new object();
            private IntPtr _context;

            internal HkdfContext()
            {
                _context = sscrypto_hkdf_ctx_new();
                if (_context == IntPtr.Zero)
                {
                    throw new System.Exception("libsscrypto: failed to create HKDF context");
                }
            }

            internal int Derive(byte[] salt, int saltLen, byte[] ikm, int ikmLen,
                byte[] info, int infoLen, byte[] okm, int okmLen)
            {
                lock (_sync)
                {
                    if (_context == IntPtr.Zero)
                    {
                        throw new ObjectDisposedException(nameof(HkdfContext));
                    }

                    return sscrypto_hkdf_ctx_derive(_context, salt, saltLen, ikm, ikmLen,
                        info, infoLen, okm, okmLen);
                }
            }

            public void Dispose()
            {
                DisposeContext();
                GC.SuppressFinalize(this);
            }

            ~HkdfContext()
            {
                DisposeContext();
            }

            private void DisposeContext()
            {
                lock (_sync)
                {
                    if (_context == IntPtr.Zero) return;
                    sscrypto_hkdf_ctx_free(_context);
                    _context = IntPtr.Zero;
                }
            }
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

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sscrypto_hkdf_ctx_new();

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sscrypto_hkdf_ctx_derive(IntPtr context,
            byte[] salt, int salt_len, byte[] ikm, int ikm_len,
            byte[] info, int info_len, byte[] okm, int okm_len);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void sscrypto_hkdf_ctx_free(IntPtr context);
    }
}
