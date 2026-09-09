using System;
using System.IO;
using System.Runtime.InteropServices;
using NLog;
using Shadowsocks.Controller;
using Shadowsocks.Properties;
using Shadowsocks.Util;

namespace Shadowsocks.Encryption
{
    /// <summary>
    /// Unpacks the bundled native crypto library and pulls it into the process.
    /// MbedTLS, OpenSSL and Sodium are all re-exports out of this single DLL, so
    /// the three of them share one unpack-and-load, guarded against the race the
    /// three separate static constructors used to have over the same temp file.
    /// </summary>
    internal static class LibSsCrypto
    {
        // x64 only. The name carries the architecture because libsscrypto builds
        // Win32 as libsscrypto.dll -- loading a leftover 32-bit copy out of the
        // temp directory would fail far from here, so the names must not collide.
        public const string DLLNAME = "libsscrypto64.dll";

        private static Logger logger = LogManager.GetCurrentClassLogger();

        private static readonly object _loadLock = new object();
        private static bool _loaded;

        public static void EnsureLoaded()
        {
            lock (_loadLock)
            {
                if (_loaded) return;

                string dllPath = Utils.GetTempPath(DLLNAME);
                try
                {
                    FileManager.UncompressFile(dllPath, Resources.libsscrypto64_dll);
                }
                catch (IOException e)
                {
                    // Another instance already has it open. That copy is the same
                    // build, so go on and load what is on disk -- but say so, since
                    // a stale file is exactly how a bad load starts.
                    logger.Warn($"Could not refresh {dllPath}, using the existing copy: {e.Message}");
                }
                catch (System.Exception e)
                {
                    logger.LogUsefulException(e);
                }

                if (LoadLibrary(dllPath) == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new DllNotFoundException(
                        $"Failed to load {dllPath} (LoadLibrary failed with error {error}). " +
                        "Shadowsocks is 64-bit and needs the x64 Visual C++ Redistributable.");
                }

                _loaded = true;
            }
        }

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string path);
    }
}
