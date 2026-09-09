using System;

namespace Shadowsocks.Model
{
    /*
     * Format:
     *  <modifiers-combination>+<key>
     *
     */

    [Serializable]
    public class HotkeyConfig
    {
        public string SwitchAllowLan;
        public string ShowLogs;
        public string ServerMoveUp;
        public string ServerMoveDown;
        public bool RegHotkeysAtStartup;

        public HotkeyConfig()
        {
            SwitchAllowLan = "";
            ShowLogs = "";
            ServerMoveUp = "";
            ServerMoveDown = "";
            RegHotkeysAtStartup = false;
        }
    }
}