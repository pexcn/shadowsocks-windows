using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Shadowsocks.Encryption
{
    /// <summary>
    /// BLAKE3, as exported by libsscrypto. Only the derive_key mode is bound:
    /// it is the one thing SIP022 needs that no other library in the DLL has,
    /// and every 2022 subkey comes out of it.
    /// </summary>
    public static class Blake3
    {
        private const string DLLNAME = LibSsCrypto.DLLNAME;

        // Not NUL-terminated: the _raw entry point takes an explicit length.
        // 31 bytes; the length is worth checking against the spec by hand.
        private static readonly byte[] SessionSubkeyContext =
            Encoding.ASCII.GetBytes("shadowsocks 2022 session subkey");

        // blake3_hasher is caller-allocated, and upstream calls its layout a
        // private detail it is free to grow, so ask rather than hardcode
        // today's 1912 bytes. The caller allocates the native context buffer.
        private static readonly int HasherSize;

        static Blake3()
        {
            // Must precede the first call: nothing else has pulled the DLL in
            // by the time a static field initialiser would run.
            LibSsCrypto.EnsureLoaded();
            HasherSize = (int)(uint)blake3_hasher_size();
        }

        /// <summary>
        /// BLAKE3 derive_key. <paramref name="output"/> is filled to its length;
        /// BLAKE3 is an XOF, so a short output is a prefix of a longer one and
        /// no truncation of our own is needed.
        /// </summary>
        public static void DeriveKey(byte[] context, byte[] keyMaterial, byte[] output)
        {
            IntPtr hasher = Marshal.AllocHGlobal(HasherSize);
            try
            {
                blake3_hasher_init_derive_key_raw(hasher, context, (UIntPtr)(uint)context.Length);
                if (keyMaterial.Length > 0)
                {
                    blake3_hasher_update(hasher, keyMaterial, (UIntPtr)(uint)keyMaterial.Length);
                }
                blake3_hasher_finalize(hasher, output, (UIntPtr)(uint)output.Length);
            }
            finally
            {
                Marshal.FreeHGlobal(hasher);
            }
        }

        /// <summary>
        /// session_subkey := derive_key("shadowsocks 2022 session subkey", PSK || salt).
        /// The key material is fed as two updates rather than concatenated.
        /// </summary>
        public static void DeriveSessionSubkey(byte[] psk, byte[] salt, byte[] subkey)
        {
            IntPtr hasher = Marshal.AllocHGlobal(HasherSize);
            try
            {
                blake3_hasher_init_derive_key_raw(hasher, SessionSubkeyContext,
                    (UIntPtr)(uint)SessionSubkeyContext.Length);
                blake3_hasher_update(hasher, psk, (UIntPtr)(uint)psk.Length);
                blake3_hasher_update(hasher, salt, (UIntPtr)(uint)salt.Length);
                blake3_hasher_finalize(hasher, subkey, (UIntPtr)(uint)subkey.Length);
            }
            finally
            {
                Marshal.FreeHGlobal(hasher);
            }
        }

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern UIntPtr blake3_hasher_size();

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void blake3_hasher_init_derive_key_raw(IntPtr self, byte[] context,
            UIntPtr contextLen);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void blake3_hasher_update(IntPtr self, byte[] input, UIntPtr inputLen);

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void blake3_hasher_finalize(IntPtr self, byte[] output, UIntPtr outputLen);
    }
}
