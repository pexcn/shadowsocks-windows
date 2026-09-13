using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using NLog;
using Shadowsocks.Controller.Service;
using Shadowsocks.Model;
using Shadowsocks.Util;

namespace Shadowsocks.Controller
{
    public class ShadowsocksController
    {
        private readonly Logger logger;
        private readonly HttpClient httpClient;

        // controller:
        // handle user actions
        // manipulates UI
        // interacts with low level logic
        #region Members definition
        private Thread _trafficThread;

        private Listener _listener;
        private Configuration _config;
        private readonly ConcurrentDictionary<Server, Sip003Plugin> _pluginsByServer;

        private long _inboundCounter = 0;
        private long _outboundCounter = 0;
        public long InboundCounter => Interlocked.Read(ref _inboundCounter);
        public long OutboundCounter => Interlocked.Read(ref _outboundCounter);
        public Queue<TrafficPerSecond> trafficPerSecondQueue;

        private bool stopped = false;

        public class UpdatedEventArgs : EventArgs
        {
            public string OldVersion;
            public string NewVersion;
        }

        public class TrafficPerSecond
        {
            public long inboundCounter;
            public long outboundCounter;
            public long inboundIncreasement;
            public long outboundIncreasement;
        }

        public event EventHandler ConfigChanged;
        public event EventHandler ShareOverLANStatusChanged;
        public event EventHandler VerboseLoggingStatusChanged;
        public event EventHandler ShowPluginOutputChanged;
        public event EventHandler TrafficChanged;

        public event ErrorEventHandler Errored;

        // Invoked when controller.Start();
        public event EventHandler<UpdatedEventArgs> ProgramUpdated;
        #endregion

        public ShadowsocksController()
        {
            logger = LogManager.GetCurrentClassLogger();
            httpClient = new HttpClient();
            _config = Configuration.Load();
            Configuration.Process(ref _config);
            _pluginsByServer = new ConcurrentDictionary<Server, Sip003Plugin>();
            StartTrafficStatistics(61);

            ProgramUpdated += (o, e) => logger.Info($"Updated from {e.OldVersion} to {e.NewVersion}");
        }

        #region Basic

        public void Start(bool systemWakeUp = false)
        {
            if (_config.firstRunOnNewVersion && !systemWakeUp)
            {
                ProgramUpdated.Invoke(this, new UpdatedEventArgs()
                {
                    OldVersion = _config.version,
                    NewVersion = UpdateChecker.Version,
                });
                // finish up first run of new version
                _config.firstRunOnNewVersion = false;
                _config.version = UpdateChecker.Version;
                Configuration.Save(_config);
            }
            Reload();
        }

        public void Stop()
        {
            if (stopped)
            {
                return;
            }
            stopped = true;
            if (_listener != null)
            {
                _listener.Stop();
            }
            StopPlugins();
            Encryption.RNG.Close();
        }

        protected void Reload()
        {
            Encryption.RNG.Reload();
            // some logic in configuration updated the config when saving, we need to read it again
            _config = Configuration.Load();
            // Configuration.Process applies the NLog configuration.
            Configuration.Process(ref _config);

            // set User-Agent for httpClient
            try
            {
                if (!string.IsNullOrWhiteSpace(_config.userAgentString))
                    httpClient.DefaultRequestHeaders.Add("User-Agent", _config.userAgentString);
            }
            catch
            {
                // reset userAgent to default and reapply
                Configuration.ResetUserAgent(_config);
                httpClient.DefaultRequestHeaders.Add("User-Agent", _config.userAgentString);
            }

            _listener?.Stop();
            StopPlugins();

            try
            {
                StartPlugin();

                TCPRelay tcpRelay = new TCPRelay(this, _config);
                tcpRelay.OnInbound += UpdateInboundCounter;
                tcpRelay.OnOutbound += UpdateOutboundCounter;

                UDPRelay udpRelay = new UDPRelay(this);
                List<Listener.IService> services = new List<Listener.IService>
                {
                    tcpRelay,
                    udpRelay
                };
                _listener = new Listener(services);
                _listener.Start(_config);
            }
            catch (Exception e)
            {
                // translate Microsoft language into human language
                // i.e. An attempt was made to access a socket in a way forbidden by its access permissions => Port already in use
                if (e is SocketException se)
                {
                    if (se.SocketErrorCode == SocketError.AddressAlreadyInUse)
                    {
                        e = new Exception(I18N.GetString("Port {0} already in use", _config.localPort), e);
                    }
                    else if (se.SocketErrorCode == SocketError.AccessDenied)
                    {
                        e = new Exception(I18N.GetString("Port {0} is reserved by system", _config.localPort), e);
                    }
                }
                logger.LogUsefulException(e);
                ReportError(e);
            }

            ConfigChanged?.Invoke(this, new EventArgs());
        }

        protected void SaveConfig(Configuration newConfig)
        {
            Configuration.Save(newConfig);
            Reload();
        }

        protected void ReportError(Exception e)
        {
            Errored?.Invoke(this, new ErrorEventArgs(e));
        }

        public HttpClient GetHttpClient() => httpClient;
        public Server GetCurrentServer() => _config.GetCurrentServer();
        public Configuration GetCurrentConfiguration() => _config;

        public void SaveServers(List<Server> servers, int localPort, bool portableMode)
        {
            _config.configs = servers;
            _config.localPort = localPort;
            _config.portableMode = portableMode;
            Configuration.Save(_config);
        }

        public void SelectServerIndex(int index)
        {
            _config.index = index;
            SaveConfig(_config);
        }

        public void ToggleShareOverLAN(bool enabled)
        {
            _config.shareOverLan = enabled;
            SaveConfig(_config);

            ShareOverLANStatusChanged?.Invoke(this, new EventArgs());
        }

        #endregion

        #region Forward Proxy

        public void SaveProxy(ForwardProxyConfig proxyConfig)
        {
            _config.proxy = proxyConfig;
            SaveConfig(_config);
        }

        #endregion

        #region  SIP002

        public bool AskAddServerBySSURL(string ssURL)
        {
            var dr = MessageBox.Show(I18N.GetString("Import from URL: {0} ?", ssURL), I18N.GetString("Shadowsocks"), MessageBoxButtons.YesNo);
            if (dr == DialogResult.Yes)
            {
                if (AddServerBySSURL(ssURL))
                {
                    MessageBox.Show(I18N.GetString("Successfully imported from {0}", ssURL));
                    return true;
                }
                else
                {
                    MessageBox.Show(I18N.GetString("Failed to import. Please check if the link is valid."));
                }
            }
            return false;
        }

        public bool AddServerBySSURL(string ssURL)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(ssURL))
                    return false;

                var servers = Server.GetServers(ssURL);
                if (servers == null || servers.Count == 0)
                    return false;

                foreach (var server in servers)
                {
                    _config.configs.Add(server);
                    if (server.warnLegacyUrl)
                        MessageBox.Show(I18N.GetString("Warning: importing {0} from a legacy ss:// link. Support for legacy ss:// links will be dropped in version 5. Make sure to update your ss:// links.", server.ToString()));
                }
                _config.index = _config.configs.Count - 1;
                SaveConfig(_config);
                return true;
            }
            catch (Exception e)
            {
                logger.LogUsefulException(e);
                return false;
            }
        }

        public string GetServerURLForCurrentServer()
        {
            return GetCurrentServer().GetURL(_config.generateLegacyUrl);
        }

        #endregion

        #region Misc

        public void ToggleVerboseLogging(bool enabled)
        {
            _config.isVerboseLogging = enabled;
            SaveConfig(_config);
            NLogConfig.ApplyConfiguration(enabled); // reload nlog

            VerboseLoggingStatusChanged?.Invoke(this, new EventArgs());
        }

        public void ToggleCheckingUpdate(bool enabled)
        {
            _config.autoCheckUpdate = enabled;
            Configuration.Save(_config);

            ConfigChanged?.Invoke(this, new EventArgs());
        }

        public void ToggleCheckingPreRelease(bool enabled)
        {
            _config.checkPreRelease = enabled;
            Configuration.Save(_config);
            ConfigChanged?.Invoke(this, new EventArgs());
        }

        public void SaveSkippedUpdateVerion(string version)
        {
            _config.skippedUpdateVersion = version;
            Configuration.Save(_config);
        }

        public void SaveLogViewerConfig(LogViewerConfig newConfig)
        {
            _config.logViewer = newConfig;
            newConfig.SaveSize();
            Configuration.Save(_config);

            ConfigChanged?.Invoke(this, new EventArgs());
        }

        #endregion

        #region Traffic counters

        public void UpdateInboundCounter(object sender, SSTransmitEventArgs args)
        {
            Interlocked.Add(ref _inboundCounter, args.length);
        }

        public void UpdateOutboundCounter(object sender, SSTransmitEventArgs args)
        {
            Interlocked.Add(ref _outboundCounter, args.length);
        }

        #endregion

        #region SIP003

        private void StartPlugin()
        {
            var server = _config.GetCurrentServer();
            GetPluginLocalEndPointIfConfigured(server);
        }

        private void StopPlugins()
        {
            foreach (var serverAndPlugin in _pluginsByServer)
            {
                serverAndPlugin.Value?.Dispose();
            }
            _pluginsByServer.Clear();
        }

        public EndPoint GetPluginLocalEndPointIfConfigured(Server server)
        {
            var plugin = _pluginsByServer.GetOrAdd(
                server,
                x => Sip003Plugin.CreateIfConfigured(x, _config.showPluginOutput));

            if (plugin == null)
            {
                return null;
            }

            try
            {
                if (plugin.StartIfNeeded())
                {
                    logger.Info(
                        $"Started SIP003 plugin for {server.Identifier()} on {plugin.LocalEndPoint} - PID: {plugin.ProcessId}");
                }
            }
            catch (Exception ex)
            {
                logger.Error("Failed to start SIP003 plugin: " + ex.Message);
                throw;
            }

            return plugin.LocalEndPoint;
        }

        public void ToggleShowPluginOutput(bool enabled)
        {
            _config.showPluginOutput = enabled;
            SaveConfig(_config);

            ShowPluginOutputChanged?.Invoke(this, new EventArgs());
        }

        #endregion

        #region Traffic Statistics

        private void StartTrafficStatistics(int queueMaxSize)
        {
            trafficPerSecondQueue = new Queue<TrafficPerSecond>();
            for (int i = 0; i < queueMaxSize; i++)
            {
                trafficPerSecondQueue.Enqueue(new TrafficPerSecond());
            }
            _trafficThread = new Thread(new ThreadStart(() => TrafficStatistics(queueMaxSize)))
            {
                IsBackground = true
            };
            _trafficThread.Start();
        }

        private void TrafficStatistics(int queueMaxSize)
        {
            TrafficPerSecond previous, current;
            while (true)
            {
                previous = trafficPerSecondQueue.Last();
                current = new TrafficPerSecond
                {
                    inboundCounter = InboundCounter,
                    outboundCounter = OutboundCounter
                };
                current.inboundIncreasement = current.inboundCounter - previous.inboundCounter;
                current.outboundIncreasement = current.outboundCounter - previous.outboundCounter;

                trafficPerSecondQueue.Enqueue(current);
                if (trafficPerSecondQueue.Count > queueMaxSize)
                    trafficPerSecondQueue.Dequeue();

                TrafficChanged?.Invoke(this, new EventArgs());

                Thread.Sleep(1000);
            }
        }

        #endregion

        #region SIP008


        public async Task<int> UpdateOnlineConfigInternal(string url)
        {
            var onlineServer = await OnlineConfigResolver.GetOnline(url);
            _config.configs = Configuration.SortByOnlineConfig(
                _config.configs
                .Where(c => c.group != url)
                .Concat(onlineServer)
                );
            logger.Info($"updated {onlineServer.Count} server from {url}");
            return onlineServer.Count;
        }

        public async Task<bool> UpdateOnlineConfig(string url)
        {
            var selected = GetCurrentServer();
            try
            {
                int count = await UpdateOnlineConfigInternal(url);
            }
            catch (Exception e)
            {
                logger.LogUsefulException(e);
                return false;
            }
            _config.index = _config.configs.IndexOf(selected);
            SaveConfig(_config);
            return true;
        }

        public async Task<List<string>> UpdateAllOnlineConfig()
        {
            var selected = GetCurrentServer();
            var failedUrls = new List<string>();
            foreach (var url in _config.onlineConfigSource)
            {
                try
                {
                    await UpdateOnlineConfigInternal(url);
                }
                catch (Exception e)
                {
                    logger.LogUsefulException(e);
                    failedUrls.Add(url);
                }
            }

            _config.index = _config.configs.IndexOf(selected);
            SaveConfig(_config);
            return failedUrls;
        }

        public void SaveOnlineConfigSource(List<string> sources)
        {
            _config.onlineConfigSource = sources;
            SaveConfig(_config);
        }

        public void RemoveOnlineConfig(string url)
        {
            _config.onlineConfigSource.RemoveAll(v => v == url);
            _config.configs = Configuration.SortByOnlineConfig(
                _config.configs.Where(c => c.group != url)
                );
            SaveConfig(_config);
        }

        #endregion
    }
}
