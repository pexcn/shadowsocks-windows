using Microsoft.VisualBasic.FileIO;
using NLog;
using Shadowsocks.Properties;
using Shadowsocks.Util;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Windows.Forms;

namespace Shadowsocks.Controller
{
    public static class I18N
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();

        private static Dictionary<string, string> _strings = new Dictionary<string, string>();

        private static void Init(string res, string locale)
        {
            using (TextFieldParser csvParser = new TextFieldParser(new StringReader(res)))
            {
                csvParser.SetDelimiters(",");
                csvParser.HasFieldsEnclosedInQuotes = true;

                // search language index
                string[] localeNames = csvParser.ReadFields();

                int enIndex = FindLocaleIndex(localeNames, "en");
                if (enIndex == -1)
                {
                    logger.Error("English translation not found");
                    return;
                }

                int targetIndex = SelectLocaleIndex(localeNames, locale);
                if (!string.Equals(localeNames[targetIndex], locale,
                    System.StringComparison.OrdinalIgnoreCase))
                {
                    logger.Info($"Using {localeNames[targetIndex]} translation for {locale}");
                }

                // read translation lines
                while (!csvParser.EndOfData)
                {
                    string[] translations = csvParser.ReadFields();
                    if (translations == null || enIndex >= translations.Length ||
                        targetIndex >= translations.Length)
                    {
                        continue;
                    }

                    string source = translations[enIndex];
                    string translation = translations[targetIndex];

                    if (string.IsNullOrWhiteSpace(source)) continue;
                    // line start with comment
                    if (source.TrimStart(' ').StartsWith("#")) continue;

                    string key = null;
                    if (source[0] == '@')
                    {
                        int separatorIndex = source.IndexOf('|');
                        if (separatorIndex > 1)
                        {
                            key = source.Substring(1, separatorIndex - 1);
                            source = source.Substring(separatorIndex + 1);
                            if (targetIndex == enIndex) translation = source;
                        }
                    }

                    if (string.IsNullOrWhiteSpace(translation))
                    {
                        // Keyed WPF entries fall back to English. Keep the
                        // existing empty-translation behavior for other rows.
                        if (key == null) continue;
                        translation = source;
                    }

                    _strings[source] = translation;
                    if (key != null) _strings[key] = translation;
                }
            }
        }

        private static int FindLocaleIndex(string[] localeNames, string locale)
        {
            for (int i = 0; i < localeNames.Length; i++)
            {
                if (string.Equals(localeNames[i], locale,
                    System.StringComparison.OrdinalIgnoreCase))
                {
                    return i;
                }
            }

            return -1;
        }

        private static int SelectLocaleIndex(string[] localeNames, string locale)
        {
            int enIndex = FindLocaleIndex(localeNames, "en");
            if (enIndex == -1) return -1;

            int exactIndex = FindLocaleIndex(localeNames, locale);
            if (exactIndex != -1) return exactIndex;

            string[] localeParts = (locale ?? string.Empty).Split('-');
            string language = localeParts[0];

            if (string.Equals(language, "zh", System.StringComparison.OrdinalIgnoreCase))
            {
                bool traditional = false;
                bool scriptSpecified = false;
                for (int i = 1; i < localeParts.Length; i++)
                {
                    string part = localeParts[i];
                    if (string.Equals(part, "Hans", System.StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(part, "Hant", System.StringComparison.OrdinalIgnoreCase))
                    {
                        traditional = string.Equals(part, "Hant",
                            System.StringComparison.OrdinalIgnoreCase);
                        scriptSpecified = true;
                        break;
                    }
                }

                if (!scriptSpecified)
                {
                    for (int i = 1; i < localeParts.Length; i++)
                    {
                        string part = localeParts[i];
                        if (string.Equals(part, "TW", System.StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(part, "HK", System.StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(part, "MO", System.StringComparison.OrdinalIgnoreCase))
                        {
                            traditional = true;
                            break;
                        }
                    }
                }

                int zhIndex = FindLocaleIndex(localeNames, traditional ? "zh-TW" : "zh-CN");
                if (zhIndex != -1) return zhIndex;
            }

            int regionalIndex = -1;
            for (int i = 0; i < localeNames.Length; i++)
            {
                string candidate = localeNames[i];
                if (!string.Equals(candidate.Split('-')[0], language,
                    System.StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (candidate.IndexOf('-') == -1) return i;
                if (regionalIndex == -1) regionalIndex = i;
            }

            return regionalIndex != -1 ? regionalIndex : enIndex;
        }

        static I18N()
        {
            string locale = CultureInfo.CurrentCulture.Name;
            logger.Info("Current language is: " + locale);
            Init(Resources.i18n_csv, locale);
        }

        public static string GetString(string key, params object[] args)
        {
            return string.Format(_strings.TryGetValue(key.Trim(), out var value) ? value : key, args);
        }

        public static void TranslateForm(Form c)
        {
            if (c == null) return;
            c.Text = GetString(c.Text);
            foreach (var item in ViewUtils.GetChildControls<Control>(c))
            {
                if (item == null) continue;
                item.Text = GetString(item.Text);
            }
            TranslateMenu(c.Menu);
        }
        public static void TranslateMenu(Menu m)
        {
            if (m == null) return;
            foreach (var item in ViewUtils.GetMenuItems(m))
            {
                if (item == null) continue;
                item.Text = GetString(item.Text);
            }
        }
    }
}
