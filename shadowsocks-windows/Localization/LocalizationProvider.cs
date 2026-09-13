using Shadowsocks.Controller;
using System;
using System.Windows.Markup;

namespace Shadowsocks.Localization
{
    public static class LocalizationProvider
    {
        public static T GetLocalizedValue<T>(string key)
        {
            if (typeof(T) != typeof(string))
                throw new NotSupportedException("Only string localization values are supported.");

            return (T)(object)I18N.GetString(key);
        }
    }

    // Keep the existing {lex:Loc Key} XAML syntax while using the CSV-backed
    // dictionary shared with the WinForms views.
    [MarkupExtensionReturnType(typeof(string))]
    public sealed class LocExtension : MarkupExtension
    {
        public LocExtension(string key)
        {
            Key = key;
        }

        [ConstructorArgument("key")]
        public string Key { get; set; }

        public override object ProvideValue(IServiceProvider serviceProvider)
        {
            return I18N.GetString(Key);
        }
    }
}
