using NLog;
using NLog.Config;
using NLog.Targets;
using System;
using System.IO;
using System.Text;

namespace Shadowsocks.Model
{
    /// <summary>
    /// Builds and applies the NLog configuration programmatically, so that no
    /// NLog.config file has to be shipped or generated next to the executable.
    /// </summary>
    public static class NLogConfig
    {
        const string LOG_FILE_RELATIVE_PATH = @"ss_win_temp\shadowsocks.log";

#if DEBUG
        private static readonly LogLevel verboseLogLevel = LogLevel.Trace;
#else
        private static readonly LogLevel verboseLogLevel = LogLevel.Debug;
#endif

        /// <summary>
        /// Absolute path of the file the logger writes to.
        /// </summary>
        public static string LogFile { get; } =
            Path.Combine(Program.WorkingDirectory, LOG_FILE_RELATIVE_PATH);

        /// <summary>
        /// Rebuild the logging configuration and apply it to the current LogManager.
        /// </summary>
        /// <param name="isVerboseLogging">Whether to also log below the Info level.</param>
        public static void ApplyConfiguration(bool isVerboseLogging)
        {
            try
            {
                var fileTarget = new FileTarget("file")
                {
                    FileName = LogFile,
                    // UTF-8 without a BOM, matching the previous XML configuration.
                    Encoding = new UTF8Encoding(false),
                    WriteBom = false,
                };

                var config = new LoggingConfiguration();
                config.AddRule(isVerboseLogging ? verboseLogLevel : LogLevel.Info, LogLevel.Fatal, fileTarget, "*");

                LogManager.Configuration = config;
            }
            catch (Exception ex)
            {
                NLog.Common.InternalLogger.Error(ex, "[shadowsocks] Failed to apply the NLog configuration");
            }
        }
    }
}
