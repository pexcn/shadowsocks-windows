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

        static Blake3()
        {
            LibSsCrypto.EnsureLoaded();
        }

        /// <summary>
        /// BLAKE3 derive_key. <paramref name="output"/> is filled to its length;
        /// BLAKE3 is an XOF, so a short output is a prefix of a longer one and
        /// no truncation of our own is needed.
        /// </summary>
        public static void DeriveKey(byte[] context, byte[] keyMaterial, byte[] output)
        {
            if (sscrypto_blake3_derive_key(context, (UIntPtr)(uint)context.Length,
                    keyMaterial, (UIntPtr)(uint)keyMaterial.Length,
                    null, UIntPtr.Zero, output, (UIntPtr)(uint)output.Length) != 0)
            {
                throw new System.Exception("libsscrypto: BLAKE3 failure");
            }
        }

        /// <summary>
        /// session_subkey := derive_key("shadowsocks 2022 session subkey", PSK || salt).
        /// The key material is fed as two updates rather than concatenated.
        /// </summary>
        public static void DeriveSessionSubkey(byte[] psk, byte[] salt, byte[] subkey)
        {
            if (sscrypto_blake3_derive_key(SessionSubkeyContext,
                    (UIntPtr)(uint)SessionSubkeyContext.Length,
                    psk, (UIntPtr)(uint)psk.Length,
                    salt, (UIntPtr)(uint)salt.Length,
                    subkey, (UIntPtr)(uint)subkey.Length) != 0)
            {
                throw new System.Exception("libsscrypto: BLAKE3 failure");
            }
        }

        [SuppressUnmanagedCodeSecurity]
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sscrypto_blake3_derive_key(
            byte[] context, UIntPtr contextLen,
            byte[] input1, UIntPtr input1Len,
            byte[] input2, UIntPtr input2Len,
            byte[] output, UIntPtr outputLen);
    }
}
