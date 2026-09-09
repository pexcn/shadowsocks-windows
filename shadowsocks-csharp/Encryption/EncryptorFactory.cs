using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using Shadowsocks.Encryption.AEAD;
using Shadowsocks.Encryption.Stream;

namespace Shadowsocks.Encryption
{
    public static class EncryptorFactory
    {
        private static Dictionary<string, Type> _registeredEncryptors = new Dictionary<string, Type>();

        private static readonly Type[] ConstructorTypes = {typeof(string), typeof(string)};

        static EncryptorFactory()
        {
            var AEADSodiumEncryptorSupportedCiphers = AEADSodiumEncryptor.SupportedCiphers();
            var PlainEncryptorSupportedCiphers = PlainEncryptor.SupportedCiphers();

            if (!Sodium.AES256GCMAvailable)
            {
                // libsodium refuses aes-256-gcm without AES-NI
                AEADSodiumEncryptorSupportedCiphers.Remove("aes-256-gcm");
            }

            // XXX: sequence matters, OpenSSL > Sodium. OpenSSL goes first for its
            // assembly implementations: AES-NI, and the stitched AES-NI GCM module.
            foreach (string method in AEADOpenSSLEncryptor.SupportedCiphers())
            {
                if (!_registeredEncryptors.ContainsKey(method))
                    _registeredEncryptors.Add(method, typeof(AEADOpenSSLEncryptor));
            }

            foreach (string method in AEADSodiumEncryptorSupportedCiphers)
            {
                if (!_registeredEncryptors.ContainsKey(method))
                    _registeredEncryptors.Add(method, typeof(AEADSodiumEncryptor));
            }

            foreach (string method in PlainEncryptorSupportedCiphers)
            {
                if (!_registeredEncryptors.ContainsKey(method))
                    _registeredEncryptors.Add(method, typeof(PlainEncryptor));
            }
        }

        public static IEncryptor GetEncryptor(string method, string password)
        {
            if (string.IsNullOrEmpty(method))
            {
                method = Model.Server.DefaultMethod;
            }

            method = method.ToLowerInvariant();
            Type t = _registeredEncryptors[method];

            ConstructorInfo c = t.GetConstructor(ConstructorTypes);
            if (c == null) throw new System.Exception("Invalid ctor");
            IEncryptor result = (IEncryptor) c.Invoke(new object[] {method, password});
            return result;
        }

        public static string DumpRegisteredEncryptor()
        {
            var sb = new StringBuilder();
            sb.Append(Environment.NewLine);
            sb.AppendLine("=========================");
            sb.AppendLine("Registered Encryptor Info");
            foreach (var encryptor in _registeredEncryptors)
            {
                sb.AppendLine(String.Format("{0}=>{1}", encryptor.Key, encryptor.Value.Name));
            }

            sb.AppendLine("=========================");
            return sb.ToString();
        }
    }
}
