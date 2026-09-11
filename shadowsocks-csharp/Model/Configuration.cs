using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;
using NLog;
using Shadowsocks.Controller;
using Shadowsocks.Encryption.AEAD;

namespace Shadowsocks.Model
{
    [Serializable]
    public class Configuration
    {
        [JsonIgnore]
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public string version;

        public List<Server> configs;

        public List<string> onlineConfigSource;

        public int index;
        public bool shareOverLan;
        public bool firstRun;
        public int localPort;
        public bool portableMode;
        public bool showPluginOutput;
        public bool autoCheckUpdate;
        public bool checkPreRelease;
        public string skippedUpdateVersion; // skip the update with this version number
        public bool isVerboseLogging;

        // hidden options
        public bool isIPv6Enabled; // for experimental ipv6 support
        public bool generateLegacyUrl; // for pre-sip002 url compatibility
        public string userAgent;

        public LogViewerConfig logViewer;
        public ForwardProxyConfig proxy;

        [JsonIgnore]
        public bool firstRunOnNewVersion;

        public Configuration()
        {
            version = UpdateChecker.Version;
            index = 0;
            shareOverLan = false;
            firstRun = true;
            localPort = 1080;
            portableMode = true;
            showPluginOutput = false;
            autoCheckUpdate = false;
            checkPreRelease = false;
            skippedUpdateVersion = "";
            isVerboseLogging = false;

            // hidden options
            isIPv6Enabled = false;
            generateLegacyUrl = false;
            userAgent = "ShadowsocksWindows/$version";

            logViewer = new LogViewerConfig();
            proxy = new ForwardProxyConfig();

            firstRunOnNewVersion = false;

            configs = new List<Server>();
            onlineConfigSource = new List<string>();
        }

        [JsonIgnore]
        public string userAgentString; // $version substituted with numeral version in it

        private static readonly string CONFIG_FILE = "gui-config.json";

        [JsonIgnore]
        public string LocalHost => isIPv6Enabled ? "[::1]" : "127.0.0.1";

        public Server GetCurrentServer()
        {
            if (index >= 0 && index < configs.Count)
                return configs[index];
            else
                return GetDefaultServer();
        }

        /// <summary>
        /// Used by multiple forms to validate a server.
        /// Communication is done by throwing exceptions.
        /// </summary>
        /// <param name="server"></param>
        public static void CheckServer(Server server)
        {
            CheckServer(server.server);
            CheckPort(server.server_port);
            CheckPassword(server.password);
            // The 2022 methods take a base64 key of an exact length, not a
            // passphrase, and getting that wrong is otherwise invisible until
            // the connection quietly fails to authenticate.
            AEAD2022Encryptor.CheckKey(server.method, server.password);
            CheckTimeout(server.timeout, Server.MaxServerTimeoutSec);
        }

        /// <summary>
        /// Loads the configuration from file.
        /// </summary>
        /// <returns>An Configuration object.</returns>
        public static Configuration Load()
        {
            Configuration config;
            if (File.Exists(CONFIG_FILE))
            {
                try
                {
                    string configContent = File.ReadAllText(CONFIG_FILE);
                    config = JsonConvert.DeserializeObject<Configuration>(configContent, new JsonSerializerSettings()
                    {
                        ObjectCreationHandling = ObjectCreationHandling.Replace
                    });
                    // An empty or "null" file deserializes to null without throwing,
                    // so fall back to defaults instead of handing out a null config.
                    if (config != null)
                        return config;
                    logger.Warn($"{CONFIG_FILE} is empty or invalid, falling back to the default configuration.");
                }
                catch (Exception e)
                {
                    if (!(e is FileNotFoundException))
                        logger.LogUsefulException(e);
                }
            }
            config = new Configuration();
            return config;
        }

        /// <summary>
        /// Process the loaded configurations and set up things.
        /// </summary>
        /// <param name="config">A reference of Configuration object.</param>
        public static void Process(ref Configuration config)
        {
            // Mark the first run of a new version.
            var appVersion = new Version(UpdateChecker.Version);
            var configVersion = new Version(config.version);
            if (appVersion.CompareTo(configVersion) > 0)
            {
                config.firstRunOnNewVersion = true;
            }
            // Add an empty server configuration
            if (config.configs.Count == 0)
                config.configs.Add(GetDefaultServer());
            // Selected server
            if (config.index < 0)
                config.index = 0;
            if (config.index >= config.configs.Count)
                config.index = config.configs.Count - 1;
            // Check OS IPv6 support
            if (!System.Net.Sockets.Socket.OSSupportsIPv6)
                config.isIPv6Enabled = false;
            config.proxy.CheckConfig();
            // Replace $version with the version number.
            config.userAgentString = config.userAgent.Replace("$version", config.version);

            // isVerboseLogging is persisted in this file, so it is authoritative here.
            NLogConfig.ApplyConfiguration(config.isVerboseLogging);
        }

        /// <summary>
        /// Saves the Configuration object to file.
        /// </summary>
        /// <param name="config">A Configuration object.</param>
        public static void Save(Configuration config)
        {
            config.configs = SortByOnlineConfig(config.configs);

            try
            {
                // Serialize before touching the file: truncating first means a
                // serialization failure or a kill during shutdown leaves a 0-byte config.
                var jsonString = JsonConvert.SerializeObject(config, Formatting.Indented);
                var tempFile = CONFIG_FILE + ".tmp";
                using (var configFileStream = File.Open(tempFile, FileMode.Create, FileAccess.Write))
                using (var configStreamWriter = new StreamWriter(configFileStream))
                {
                    configStreamWriter.Write(jsonString);
                    configStreamWriter.Flush();
                    configFileStream.Flush(true);
                }
                if (File.Exists(CONFIG_FILE))
                    File.Replace(tempFile, CONFIG_FILE, null);
                else
                    File.Move(tempFile, CONFIG_FILE);
            }
            catch (Exception e)
            {
                logger.LogUsefulException(e);
            }
        }

        public static List<Server> SortByOnlineConfig(IEnumerable<Server> servers)
        {
            var groups = servers.GroupBy(s => s.group);
            List<Server> ret = new List<Server>();
            ret.AddRange(groups.Where(g => string.IsNullOrEmpty(g.Key)).SelectMany(g => g));
            ret.AddRange(groups.Where(g => !string.IsNullOrEmpty(g.Key)).SelectMany(g => g));
            return ret;
        }

        public static void ResetUserAgent(Configuration config)
        {
            config.userAgent = "ShadowsocksWindows/$version";
            config.userAgentString = config.userAgent.Replace("$version", config.version);
        }

        public static Server AddDefaultServerOrServer(Configuration config, Server server = null, int? index = null)
        {
            if (config?.configs != null)
            {
                server = (server ?? GetDefaultServer());

                config.configs.Insert(index.GetValueOrDefault(config.configs.Count), server);

                //if (index.HasValue)
                //    config.configs.Insert(index.Value, server);
                //else
                //    config.configs.Add(server);
            }
            return server;
        }

        public static Server GetDefaultServer()
        {
            return new Server();
        }

        public static void CheckPort(int port)
        {
            if (port <= 0 || port > 65535)
                throw new ArgumentException(I18N.GetString("Port out of range"));
        }

        private static void CheckPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException(I18N.GetString("Password can not be blank"));
        }

        public static void CheckServer(string server)
        {
            if (string.IsNullOrEmpty(server))
                throw new ArgumentException(I18N.GetString("Server IP can not be blank"));
        }

        public static void CheckTimeout(int timeout, int maxTimeout)
        {
            if (timeout <= 0 || timeout > maxTimeout)
                throw new ArgumentException(
                    I18N.GetString("Timeout is invalid, it should not exceed {0}", maxTimeout));
        }
    }
}
