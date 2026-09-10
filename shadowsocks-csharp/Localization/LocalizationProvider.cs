using WPFLocalizeExtension.Extensions;

namespace Shadowsocks.Localization
{
    public static class LocalizationProvider
    {
        // Strings lives in Shadowsocks.Localization.dll, not in this assembly, so
        // the key cannot be built from the calling assembly any more. Reading the
        // name off the type keeps it in step with the project reference; the XAML
        // views spell out the same name in ResxLocalizationProvider.DefaultAssembly.
        private static readonly string StringsAssembly = typeof(Strings).Assembly.GetName().Name;

        public static T GetLocalizedValue<T>(string key)
        {
            return LocExtension.GetLocalizedValue<T>(StringsAssembly + ":Strings:" + key);
        }
    }
}
