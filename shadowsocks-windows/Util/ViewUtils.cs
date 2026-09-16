using Shadowsocks.Controller;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Shadowsocks.Util
{
    public static class ViewUtils
    {
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyIcon(IntPtr hIcon);

        public static Icon CreateIcon(Bitmap bitmap)
        {
            if (bitmap == null) throw new ArgumentNullException(nameof(bitmap));

            IntPtr handle = bitmap.GetHicon();
            try
            {
                using (Icon borrowed = Icon.FromHandle(handle))
                {
                    // NotifyIcon keeps the Icon instance, so return an owned copy
                    // before releasing the HICON returned by Bitmap.GetHicon().
                    return (Icon)borrowed.Clone();
                }
            }
            finally
            {
                DestroyIcon(handle);
            }
        }

        public static void SetFormIcon(Form form, Bitmap bitmap)
        {
            if (form == null) throw new ArgumentNullException(nameof(form));
            if (bitmap == null) throw new ArgumentNullException(nameof(bitmap));

            Icon icon = CreateIcon(bitmap);
            EventHandler disposeIcon = null;
            disposeIcon = (sender, e) =>
            {
                form.Disposed -= disposeIcon;
                icon.Dispose();
            };

            try
            {
                // Form.Icon retains the assigned Icon instance rather than
                // cloning it, so keep the icon alive for the form's lifetime.
                form.Disposed += disposeIcon;
                form.Icon = icon;
            }
            catch
            {
                form.Disposed -= disposeIcon;
                icon.Dispose();
                throw;
            }
        }

        public static IEnumerable<TControl> GetChildControls<TControl>(this Control control) where TControl : Control
        {
            if (control.Controls.Count == 0)
            {
                return Enumerable.Empty<TControl>();
            }
            var children = control.Controls.OfType<TControl>().ToList();
            return children.SelectMany(GetChildControls<TControl>).Concat(children);
        }

        public static IEnumerable<MenuItem> GetMenuItems(Menu m)
        {
            if (m?.MenuItems == null || m.MenuItems.Count == 0) return Enumerable.Empty<MenuItem>();
            var children = new List<MenuItem>();
            foreach (var item in m.MenuItems)
            {
                children.Add((MenuItem)item);
            }
            return children.SelectMany(GetMenuItems).Concat(children);
        }

        // Workaround NotifyIcon's 63 chars limit
        // https://stackoverflow.com/questions/579665/how-can-i-show-a-systray-tooltip-longer-than-63-chars
        public static void SetNotifyIconText(NotifyIcon ni, string text)
        {
            if (text.Length >= 128)
                throw new ArgumentOutOfRangeException("Text limited to 127 characters");
            Type t = typeof(NotifyIcon);
            BindingFlags hidden = BindingFlags.NonPublic | BindingFlags.Instance;
            t.GetField("text", hidden).SetValue(ni, text);
            if ((bool)t.GetField("added", hidden).GetValue(ni))
                t.GetMethod("UpdateIcon", hidden).Invoke(ni, new object[] { true });
        }

        public static Bitmap AddBitmapOverlay(Bitmap original, params Bitmap[] overlays)
        {
            Bitmap bitmap = new Bitmap(original.Width, original.Height, PixelFormat.Format64bppArgb);
            try
            {
                using (Graphics canvas = Graphics.FromImage(bitmap))
                {
                    canvas.DrawImage(original, new Point(0, 0));
                    foreach (Bitmap overlay in overlays)
                    {
                        using (Bitmap resized = new Bitmap(overlay, original.Size))
                        {
                            canvas.DrawImage(resized, new Point(0, 0));
                        }
                    }
                }
                return bitmap;
            }
            catch
            {
                bitmap.Dispose();
                throw;
            }
        }

        public static Bitmap ChangeBitmapColor(Bitmap original, Color colorMask)
        {
            Bitmap newBitmap = new Bitmap(original);

            for (int x = 0; x < newBitmap.Width; x++)
            {
                for (int y = 0; y < newBitmap.Height; y++)
                {
                    Color color = original.GetPixel(x, y);
                    if (color.A != 0)
                    {
                        int red = color.R * colorMask.R / 255;
                        int green = color.G * colorMask.G / 255;
                        int blue = color.B * colorMask.B / 255;
                        int alpha = color.A * colorMask.A / 255;
                        newBitmap.SetPixel(x, y, Color.FromArgb(alpha, red, green, blue));
                    }
                    else
                    {
                        newBitmap.SetPixel(x, y, color);
                    }
                }
            }
            return newBitmap;
        }

        public static Bitmap ResizeBitmap(Bitmap original, int width, int height)
        {
            Bitmap newBitmap = new Bitmap(width, height);
            try
            {
                using (Graphics g = Graphics.FromImage(newBitmap))
                {
                    g.SmoothingMode = SmoothingMode.HighQuality;
                    g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                    g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                    g.CompositingQuality = CompositingQuality.HighQuality;
                    g.DrawImage(original, new Rectangle(0, 0, width, height));
                }
                return newBitmap;
            }
            catch
            {
                newBitmap.Dispose();
                throw;
            }
        }

        public static int GetScreenDpi()
        {
            using (Graphics graphics = Graphics.FromHwnd(IntPtr.Zero))
            {
                return (int)graphics.DpiX;
            }
        }
    }
}
