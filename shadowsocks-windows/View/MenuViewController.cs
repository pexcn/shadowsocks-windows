using Shadowsocks.Controller;
using Shadowsocks.Localization;
using Shadowsocks.Model;
using Shadowsocks.Properties;
using Shadowsocks.Util;
using Shadowsocks.Views;
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using System.Windows.Forms.Integration;
using System.Windows.Threading;
using ZXing;
using ZXing.Common;
using ZXing.QrCode;

namespace Shadowsocks.View
{
    public class MenuViewController
    {
        private ShadowsocksController controller;
        public UpdateChecker updateChecker;

        private NotifyIcon _notifyIcon;
        private Icon icon, icon_in, icon_out, icon_both, previousIcon;

        private bool _isStartupCheck;
        private string _urlToOpen;

        private ContextMenu contextMenu1;
        private MenuItem AutoStartupItem;
        private MenuItem ShareOverLANItem;
        private MenuItem SeperatorItem;
        private MenuItem ConfigItem;
        private MenuItem ServersItem;
        private MenuItem autoCheckUpdatesToggleItem;
        private MenuItem checkPreReleaseToggleItem;
        private MenuItem proxyItem;
        private MenuItem VerboseLoggingToggleItem;
        private MenuItem ShowPluginOutputToggleItem;
        private MenuItem onlineConfigItem;

        private ConfigForm configForm;
        private LogForm logForm;

        private System.Windows.Window serverSharingWindow;
        private System.Windows.Window forwardProxyWindow;
        private System.Windows.Window onlineConfigWindow;

        // color definition for icon color transformation
        private readonly Color colorMaskEclipse = Color.FromArgb(192, 64, 64, 64);

        public MenuViewController(ShadowsocksController controller)
        {
            this.controller = controller;

            LoadMenu();

            controller.ConfigChanged += controller_ConfigChanged;
            controller.ShareOverLANStatusChanged += controller_ShareOverLANStatusChanged;
            controller.VerboseLoggingStatusChanged += controller_VerboseLoggingStatusChanged;
            controller.ShowPluginOutputChanged += controller_ShowPluginOutputChanged;
            controller.Errored += controller_Errored;

            _notifyIcon = new NotifyIcon();
            UpdateTrayIconAndNotifyText();
            _notifyIcon.Visible = true;
            _notifyIcon.ContextMenu = contextMenu1;
            _notifyIcon.BalloonTipClicked += notifyIcon1_BalloonTipClicked;
            _notifyIcon.MouseClick += notifyIcon1_Click;
            _notifyIcon.MouseDoubleClick += notifyIcon1_DoubleClick;
            _notifyIcon.BalloonTipClosed += _notifyIcon_BalloonTipClosed;
            controller.TrafficChanged += controller_TrafficChanged;

            updateChecker = new UpdateChecker();
            updateChecker.CheckUpdateCompleted += updateChecker_CheckUpdateCompleted;

            LoadCurrentConfiguration();

            Configuration config = controller.GetCurrentConfiguration();

            if (config.firstRun)
            {
                ShowConfigForm();
            }
            else if (config.autoCheckUpdate)
            {
                _isStartupCheck = true;
                Dispatcher.CurrentDispatcher.Invoke(() => updateChecker.CheckForVersionUpdate(3000));
            }
        }

        #region Tray Icon

        private void UpdateTrayIconAndNotifyText()
        {
            Configuration config = controller.GetCurrentConfiguration();

            Color colorMask = SelectColorMask();
            Size iconSize = SelectIconSize();

            UpdateIconSet(colorMask, iconSize, out icon, out icon_in, out icon_out, out icon_both);

            previousIcon = icon;
            _notifyIcon.Icon = previousIcon;

            string serverInfo = config.GetCurrentServer().ToString();
            // show more info by hacking the P/Invoke declaration for NOTIFYICONDATA inside Windows Forms
            // this feedback is very important because they need to know Shadowsocks is running
            string text = I18N.GetString("Shadowsocks") + " " + UpdateChecker.Version + "\n" +
                          I18N.GetString("Running: Port {0}", config.localPort)
                          + "\n" + serverInfo;
            if (text.Length > 127)
            {
                text = text.Substring(0, 126 - 3) + "...";
            }
            ViewUtils.SetNotifyIconText(_notifyIcon, text);
        }

        /// <summary>
        /// Determine the icon size based on the screen DPI.
        /// </summary>
        /// <returns></returns>
        /// https://stackoverflow.com/a/40851713/2075611
        private Size SelectIconSize()
        {
            Size size = new Size(32, 32);
            int dpi = ViewUtils.GetScreenDpi();
            if (dpi < 97)
            {
                // dpi = 96;
                size = new Size(16, 16);
            }
            else if (dpi < 121)
            {
                // dpi = 120;
                size = new Size(20, 20);
            }
            else if (dpi < 145)
            {
                // dpi = 144;
                size = new Size(24, 24);
            }
            else
            {
                // dpi = 168;
                size = new Size(28, 28);
            }
            return size;
        }

        private Color SelectColorMask()
        {
            // dark tray backgrounds need the light icon, and vice versa
            return Utils.GetWindows10SystemThemeSetting() == Utils.WindowsThemeMode.Light
                ? colorMaskEclipse
                : Color.White;
        }

        private void UpdateIconSet(Color colorMask, Size size,
            out Icon icon, out Icon icon_in, out Icon icon_out, out Icon icon_both)
        {
            Bitmap iconBitmap;

            // generate the base icon
            iconBitmap = ViewUtils.ChangeBitmapColor(Resources.ss32Fill, colorMask);
            iconBitmap = ViewUtils.AddBitmapOverlay(iconBitmap, Resources.ss32Outline);

            icon = Icon.FromHandle(ViewUtils.ResizeBitmap(iconBitmap, size.Width, size.Height).GetHicon());
            icon_in = Icon.FromHandle(ViewUtils.ResizeBitmap(ViewUtils.AddBitmapOverlay(iconBitmap, Resources.ss32In), size.Width, size.Height).GetHicon());
            icon_out = Icon.FromHandle(ViewUtils.ResizeBitmap(ViewUtils.AddBitmapOverlay(iconBitmap, Resources.ss32In), size.Width, size.Height).GetHicon());
            icon_both = Icon.FromHandle(ViewUtils.ResizeBitmap(ViewUtils.AddBitmapOverlay(iconBitmap, Resources.ss32In, Resources.ss32Out), size.Width, size.Height).GetHicon());
        }

        #endregion

        #region MenuItems and MenuGroups

        private MenuItem CreateMenuItem(string text, EventHandler click)
        {
            return new MenuItem(I18N.GetString(text), click);
        }

        private MenuItem CreateMenuGroup(string text, MenuItem[] items)
        {
            return new MenuItem(I18N.GetString(text), items);
        }

        private void LoadMenu()
        {
            this.contextMenu1 = new ContextMenu(new MenuItem[] {
                this.ServersItem = CreateMenuGroup("Servers", new MenuItem[] {
                    this.SeperatorItem = new MenuItem("-"),
                    this.ConfigItem = CreateMenuItem("Edit Servers...", new EventHandler(this.Config_Click)),
                    new MenuItem("-"),
                    CreateMenuItem("Share Server Config...", new EventHandler(this.QRCodeItem_Click)),
                    CreateMenuItem("Scan QRCode from Screen...", new EventHandler(this.ScanQRCodeItem_Click)),
                    CreateMenuItem("Import URL from Clipboard...", new EventHandler(this.ImportURLItem_Click))
                }),
                this.proxyItem = CreateMenuItem("Forward Proxy...", new EventHandler(this.proxyItem_Click)),
                this.onlineConfigItem = CreateMenuItem("Online Config...", new EventHandler(this.OnlineConfig_Click)),
                new MenuItem("-"),
                this.AutoStartupItem = CreateMenuItem("Start on Boot", new EventHandler(this.AutoStartupItem_Click)),
                this.ShareOverLANItem = CreateMenuItem("Allow LAN connections", new EventHandler(this.ShareOverLANItem_Click)),
                new MenuItem("-"),
                CreateMenuGroup("Help", new MenuItem[] {
                    CreateMenuItem("Show Logs...", new EventHandler(this.ShowLogItem_Click)),
                    this.VerboseLoggingToggleItem = CreateMenuItem( "Verbose Logging", new EventHandler(this.VerboseLoggingToggleItem_Click) ),
                    this.ShowPluginOutputToggleItem = CreateMenuItem("Show Plugin Output", new EventHandler(this.ShowPluginOutputToggleItem_Click)),
                    CreateMenuGroup("Updates...", new MenuItem[] {
                        CreateMenuItem("Check for Updates...", new EventHandler(this.checkUpdatesItem_Click)),
                        new MenuItem("-"),
                        this.autoCheckUpdatesToggleItem = CreateMenuItem("Check for Updates at Startup", new EventHandler(this.autoCheckUpdatesToggleItem_Click)),
                        this.checkPreReleaseToggleItem = CreateMenuItem("Check Pre-release Version", new EventHandler(this.checkPreReleaseToggleItem_Click)),
                    }),
                    CreateMenuItem("About...", new EventHandler(this.AboutItem_Click)),
                }),
                new MenuItem("-"),
                CreateMenuItem("Quit", new EventHandler(this.Quit_Click))
            });
        }

        #endregion

        private void controller_TrafficChanged(object sender, EventArgs e)
        {
            if (icon == null)
                return;

            Icon newIcon;

            bool hasInbound = controller.trafficPerSecondQueue.Last().inboundIncreasement > 0;
            bool hasOutbound = controller.trafficPerSecondQueue.Last().outboundIncreasement > 0;

            if (hasInbound && hasOutbound)
                newIcon = icon_both;
            else if (hasInbound)
                newIcon = icon_in;
            else if (hasOutbound)
                newIcon = icon_out;
            else
                newIcon = icon;

            if (newIcon != this.previousIcon)
            {
                this.previousIcon = newIcon;
                _notifyIcon.Icon = newIcon;
            }
        }

        void controller_Errored(object sender, ErrorEventArgs e)
        {
            MessageBox.Show(e.GetException().ToString(), I18N.GetString("Shadowsocks Error: {0}", e.GetException().Message));
        }

        private void controller_ConfigChanged(object sender, EventArgs e)
        {
            LoadCurrentConfiguration();
            UpdateTrayIconAndNotifyText();
        }

        private void LoadCurrentConfiguration()
        {
            Configuration config = controller.GetCurrentConfiguration();
            UpdateServersMenu();
            ShareOverLANItem.Checked = config.shareOverLan;
            VerboseLoggingToggleItem.Checked = config.isVerboseLogging;
            ShowPluginOutputToggleItem.Checked = config.showPluginOutput;
            AutoStartupItem.Checked = AutoStartup.Check();
            UpdateUpdateMenu();
        }

        #region Forms

        private void ShowConfigForm()
        {
            if (configForm != null)
            {
                configForm.Activate();
            }
            else
            {
                configForm = new ConfigForm(controller);
                configForm.Show();
                configForm.Activate();
                configForm.FormClosed += configForm_FormClosed;
            }
        }

        private void ShowLogForm()
        {
            if (logForm != null)
            {
                logForm.Activate();
            }
            else
            {
                logForm = new LogForm(controller);
                logForm.Show();
                logForm.Activate();
                logForm.FormClosed += logForm_FormClosed;
            }
        }

        void logForm_FormClosed(object sender, FormClosedEventArgs e)
        {
            logForm.Dispose();
            logForm = null;
        }

        void configForm_FormClosed(object sender, FormClosedEventArgs e)
        {
            configForm.Dispose();
            configForm = null;
            var config = controller.GetCurrentConfiguration();
            if (config.firstRun)
            {
                CheckUpdateForFirstRun();
                ShowBalloonTip(
                    I18N.GetString("Shadowsocks is here"),
                    I18N.GetString("You can turn on/off Shadowsocks in the context menu"),
                    ToolTipIcon.Info,
                    0
                );
                config.firstRun = false;
            }
        }

        #endregion

        #region Misc

        void ShowBalloonTip(string title, string content, ToolTipIcon icon, int timeout)
        {
            _notifyIcon.BalloonTipTitle = title;
            _notifyIcon.BalloonTipText = content;
            _notifyIcon.BalloonTipIcon = icon;
            _notifyIcon.ShowBalloonTip(timeout);
        }

        void notifyIcon1_BalloonTipClicked(object sender, EventArgs e)
        {
        }

        private void _notifyIcon_BalloonTipClosed(object sender, EventArgs e)
        {
        }

        private void notifyIcon1_Click(object sender, MouseEventArgs e)
        {
            UpdateTrayIconAndNotifyText();
            if (e.Button == MouseButtons.Middle)
            {
                ShowLogForm();
            }
        }

        private void notifyIcon1_DoubleClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                ShowConfigForm();
            }
        }

        private void CheckUpdateForFirstRun()
        {
            Configuration config = controller.GetCurrentConfiguration();
            if (config.firstRun)
                return;
            _isStartupCheck = true;
            Dispatcher.CurrentDispatcher.Invoke(() => updateChecker.CheckForVersionUpdate(3000));
        }

        #endregion

        #region Main menu

        void controller_ShareOverLANStatusChanged(object sender, EventArgs e)
        {
            ShareOverLANItem.Checked = controller.GetCurrentConfiguration().shareOverLan;
        }

        private void proxyItem_Click(object sender, EventArgs e)
        {
            if (forwardProxyWindow == null)
            {
                forwardProxyWindow = new System.Windows.Window()
                {
                    Title = LocalizationProvider.GetLocalizedValue<string>("ForwardProxy"),
                    Height = 400,
                    Width = 280,
                    MinHeight = 400,
                    MinWidth = 280,
                    Content = new ForwardProxyView()
                };
                forwardProxyWindow.Closed += ForwardProxyWindow_Closed;
                ElementHost.EnableModelessKeyboardInterop(forwardProxyWindow);
                forwardProxyWindow.Show();
            }
            forwardProxyWindow.Activate();
        }

        private void ForwardProxyWindow_Closed(object sender, EventArgs e)
        {
            forwardProxyWindow = null;
        }

        public void CloseForwardProxyWindow() => forwardProxyWindow.Close();

        private void OnlineConfig_Click(object sender, EventArgs e)
        {
            if (onlineConfigWindow == null)
            {
                onlineConfigWindow = new System.Windows.Window()
                {
                    Title = LocalizationProvider.GetLocalizedValue<string>("OnlineConfigDelivery"),
                    Height = 510,
                    Width = 480,
                    MinHeight = 510,
                    MinWidth = 480,
                    Content = new OnlineConfigView()
                };
                onlineConfigWindow.Closed += OnlineConfigWindow_Closed;
                ElementHost.EnableModelessKeyboardInterop(onlineConfigWindow);
                onlineConfigWindow.Show();
            }
            onlineConfigWindow.Activate();
        }

        private void OnlineConfigWindow_Closed(object sender, EventArgs e)
        {
            onlineConfigWindow = null;
        }

        private void ShareOverLANItem_Click(object sender, EventArgs e)
        {
            ShareOverLANItem.Checked = !ShareOverLANItem.Checked;
            controller.ToggleShareOverLAN(ShareOverLANItem.Checked);
        }

        private void AutoStartupItem_Click(object sender, EventArgs e)
        {
            AutoStartupItem.Checked = !AutoStartupItem.Checked;
            if (!AutoStartup.Set(AutoStartupItem.Checked))
            {
                MessageBox.Show(I18N.GetString("Failed to update registry"));
            }
            LoadCurrentConfiguration();
        }

        private void Quit_Click(object sender, EventArgs e)
        {
            controller.Stop();
            _notifyIcon.Visible = false;
            Application.Exit();
        }

        #endregion

        #region Server

        private void UpdateServersMenu()
        {
            var items = ServersItem.MenuItems;
            while (items[0] != SeperatorItem)
            {
                items.RemoveAt(0);
            }
            int maxCount = 20;
            int serverCount = 0;
            bool overflow = false;
            bool needAdd = true;
            
            Configuration configuration = controller.GetCurrentConfiguration();
            for (int i = 0; i < configuration.configs.Count; i++)
            {
                try
                {
                    if (overflow)
                    {
                        needAdd = configuration.index >= i;
                        if (needAdd)
                        {
                            i = configuration.index;
                        }
                    }

                    if (needAdd)
                    {
                        var server = configuration.configs[i];
                        Configuration.CheckServer(server);
                        var item = new MenuItem(server.ToString());
                        item.Tag = i;
                        item.Click += AServerItem_Click;
                        items.Add(serverCount, item);
                        serverCount++;
                    }
                    
                    if (overflow)
                    {
                        items.Add(serverCount, new MenuItem($"... more than {maxCount} (total {configuration.configs.Count})", Config_Click));
                        break;
                    }

                    overflow = serverCount > maxCount;
                }
                catch
                {
                }
            }

            foreach (MenuItem item in items)
            {
                if (item.Tag != null && item.Tag.ToString() == configuration.index.ToString())
                {
                    item.Checked = true;
                }
            }
        }

        private void AServerItem_Click(object sender, EventArgs e)
        {
            MenuItem item = (MenuItem)sender;
            controller.SelectServerIndex((int)item.Tag);
        }

        private void Config_Click(object sender, EventArgs e)
        {
            ShowConfigForm();
        }

        void openURLFromQRCode()
        {
            Process.Start(_urlToOpen);
        }

        private void QRCodeItem_Click(object sender, EventArgs e)
        {
            if (serverSharingWindow == null)
            {
                serverSharingWindow = new System.Windows.Window()
                {
                    Title = LocalizationProvider.GetLocalizedValue<string>("ServerSharing"),
                    Height = 400,
                    Width = 660,
                    MinHeight = 400,
                    MinWidth = 660,
                    Content = new ServerSharingView()
                };
                serverSharingWindow.Closed += ServerSharingWindow_Closed;
                ElementHost.EnableModelessKeyboardInterop(serverSharingWindow);
                serverSharingWindow.Show();
            }
            serverSharingWindow.Activate();
        }

        private void ServerSharingWindow_Closed(object sender, EventArgs e)
        {
            serverSharingWindow = null;
        }

        private void ScanQRCodeItem_Click(object sender, EventArgs e)
        {
            var result = Utils.ScanQRCodeFromScreen();
            if (result != null)
            {
                if (result.ToLowerInvariant().StartsWith("http://") || result.ToLowerInvariant().StartsWith("https://"))
                {
                    _urlToOpen = result;
                    openURLFromQRCode();
                }
                else if (controller.AddServerBySSURL(result))
                {
                    ShowConfigForm();
                }
                else
                {
                    MessageBox.Show(I18N.GetString("Invalid QR Code content: {0}", result));
                }
                return;
            }
            else
                MessageBox.Show(I18N.GetString("No QRCode found. Try to zoom in or move it to the center of the screen."));
        }

        private void ImportURLItem_Click(object sender, EventArgs e)
        {
            if (controller.AskAddServerBySSURL(Clipboard.GetText(TextDataFormat.Text)))
            {
                ShowConfigForm();
            }
        }

        #endregion

        #region Help

        void controller_VerboseLoggingStatusChanged(object sender, EventArgs e)
        {
            VerboseLoggingToggleItem.Checked = controller.GetCurrentConfiguration().isVerboseLogging;
        }

        void controller_ShowPluginOutputChanged(object sender, EventArgs e)
        {
            ShowPluginOutputToggleItem.Checked = controller.GetCurrentConfiguration().showPluginOutput;
        }

        private void VerboseLoggingToggleItem_Click(object sender, EventArgs e)
        {
            VerboseLoggingToggleItem.Checked = !VerboseLoggingToggleItem.Checked;
            controller.ToggleVerboseLogging(VerboseLoggingToggleItem.Checked);
        }

        private void ShowLogItem_Click(object sender, EventArgs e)
        {
            ShowLogForm();
        }

        private void ShowPluginOutputToggleItem_Click(object sender, EventArgs e)
        {
            ShowPluginOutputToggleItem.Checked = !ShowPluginOutputToggleItem.Checked;
            controller.ToggleShowPluginOutput(ShowPluginOutputToggleItem.Checked);
        }

        #endregion

        #region Update

        void updateChecker_CheckUpdateCompleted(object sender, EventArgs e)
        {
            if (!_isStartupCheck && updateChecker.NewReleaseZipFilename == null)
            {
                ShowBalloonTip(I18N.GetString("Shadowsocks"), I18N.GetString("No update is available"), ToolTipIcon.Info, 5000);
            }
            _isStartupCheck = false;
        }

        private void UpdateUpdateMenu()
        {
            Configuration configuration = controller.GetCurrentConfiguration();
            autoCheckUpdatesToggleItem.Checked = configuration.autoCheckUpdate;
            checkPreReleaseToggleItem.Checked = configuration.checkPreRelease;
        }

        private void autoCheckUpdatesToggleItem_Click(object sender, EventArgs e)
        {
            Configuration configuration = controller.GetCurrentConfiguration();
            controller.ToggleCheckingUpdate(!configuration.autoCheckUpdate);
            UpdateUpdateMenu();
        }

        private void checkPreReleaseToggleItem_Click(object sender, EventArgs e)
        {
            Configuration configuration = controller.GetCurrentConfiguration();
            controller.ToggleCheckingPreRelease(!configuration.checkPreRelease);
            UpdateUpdateMenu();
        }

        private async void checkUpdatesItem_Click(object sender, EventArgs e)
        {
            await updateChecker.CheckForVersionUpdate();
        }

        private void AboutItem_Click(object sender, EventArgs e)
        {
            Process.Start("https://github.com/pexcn/shadowsocks-windows");
        }

        #endregion
    }
}
