<img src="shadowsocks-csharp/Resources/ssw128.png" alt="[logo]" width="48"/> Shadowsocks for Windows
=======================

[![Build Status]][Actions]

[中文说明]

## Features

1. Supports server auto switching
2. Supports UDP relay (see Usage)
3. Supports plugins

## Downloads

Download the latest release from [release page].

## Requirements

.NET Framework 4.8 or higher, Microsoft [Visual C++ 2015 Redistributable] (x64) .

## Basics

1. Find Shadowsocks icon in the notification tray
2. You can add multiple servers in servers menu
3. Configure your browser or application to use the local SOCKS5 proxy at
127.0.0.1:1080. You can change this port in `Servers -> Edit Servers`

## UDP

For UDP, you need to use SocksCap or ProxyCap to force programs you want
to be proxied to tunnel over Shadowsocks

## Multiple Instances

If you want to manage multiple servers using other tools like SwitchyOmega,
you can start multiple Shadowsocks instances. To avoid configuration conflicts,
copy Shadowsocks to a new directory and choose a different local port.

## Plugins

If you would like to connect to server via a plugin, please set the plugin's
path (relative or absolute) on Edit Servers form.
_Note_: Forward Proxy will not be used while a plugin is enabled.

Details:
[Working with non SIP003 standard Plugin].

## Server Configuration

Please visit [Servers] for more information.

## Experimental

[Experimental Features]

## Development

1. Visual Studio 2019 & .NET Framework 4.8 SDK are required.
2. It is recommended to share your idea on the Issue Board before you start to work,
especially for feature development.

## License

[GPLv3]

## Open Source Components / Libraries

```
Caseless.Fody (MIT)              https://github.com/Fody/Caseless
Costura.Fody (MIT)               https://github.com/Fody/Costura
Fody (MIT)                       https://github.com/Fody/Fody
MdXaml (MIT)                     https://github.com/whistyun/MdXaml
Newtonsoft.Json (MIT)            https://www.newtonsoft.com/json
ReactiveUI.WPF (MIT)             https://github.com/reactiveui/ReactiveUI
ReactiveUI.Events.WPF (MIT)      https://github.com/reactiveui/ReactiveUI
ReactiveUI.Fody (MIT)            https://github.com/reactiveui/ReactiveUI
ReactiveUI.Validation (MIT)      https://github.com/reactiveui/ReactiveUI.Validation
WPFLocalizationExtension (MS-PL) https://github.com/XAMLMarkupExtensions/WPFLocalizationExtension/
ZXing.Net (Apache 2.0)           https://github.com/micjahn/ZXing.Net

libsscrypto (GPLv2)    https://github.com/shadowsocks/libsscrypto
```



[Actions]:      https://github.com/pexcn/shadowsocks-windows/actions
[Build Status]: https://github.com/pexcn/shadowsocks-windows/actions/workflows/build.yml/badge.svg
[release page]: https://github.com/pexcn/shadowsocks-windows/releases
[Servers]:      https://github.com/shadowsocks/shadowsocks/wiki/Ports-and-Clients#linux--server-side
[中文说明]:     https://github.com/shadowsocks/shadowsocks-windows/wiki/Shadowsocks-Windows-%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E
[Visual C++ 2015 Redistributable]:     https://www.microsoft.com/en-us/download/details.aspx?id=53840
[GPLv3]:        https://github.com/shadowsocks/shadowsocks-windows/blob/master/LICENSE.txt
[Working with non SIP003 standard Plugin]: https://github.com/shadowsocks/shadowsocks-windows/wiki/Working-with-non-SIP003-standard-Plugin
[Experimental Features]: https://github.com/shadowsocks/shadowsocks-windows/wiki/Experimental