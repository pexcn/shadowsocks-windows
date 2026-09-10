using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using NLog;
using Shadowsocks.Controller.Strategy;
using Shadowsocks.Encryption;
using Shadowsocks.Encryption.Exception;
using Shadowsocks.Model;

namespace Shadowsocks.Controller
{
    class UDPRelay : Listener.Service
    {
        private ShadowsocksController _controller;

        // TODO: choose a smart number
        private LRUCache<IPEndPoint, UDPHandler> _cache = new LRUCache<IPEndPoint, UDPHandler>(512);

        public long outbound = 0;
        public long inbound = 0;

        public UDPRelay(ShadowsocksController controller)
        {
            this._controller = controller;
        }

        public override bool Handle(byte[] firstPacket, int length, Socket socket, object state)
        {
            if (socket.ProtocolType != ProtocolType.Udp)
            {
                return false;
            }
            if (length < 4)
            {
                return false;
            }
            Listener.UDPState udpState = (Listener.UDPState)state;
            IPEndPoint remoteEndPoint = (IPEndPoint)udpState.remoteEndPoint;
            UDPHandler handler = _cache.get(remoteEndPoint);
            if (handler == null)
            {
                handler = new UDPHandler(socket, _controller.GetAServer(IStrategyCallerType.UDP, remoteEndPoint, null/*TODO: fix this*/), remoteEndPoint);
                handler.Receive();
                _cache.add(remoteEndPoint, handler);
            }
            handler.Send(firstPacket, length);
            return true;
        }

        public class UDPHandler
        {
            private static Logger logger = LogManager.GetCurrentClassLogger();

            private Socket _local;
            private Socket _remote;

            private Server _server;
            private byte[] _buffer = new byte[65536];

            // One per handler, not one per datagram: the 2022 methods carry a
            // session id, a packet id counter and a replay window across the
            // packets of a session, and rebuilding it each time would throw all
            // of that away.
            private readonly IEncryptor _encryptor;

            private IPEndPoint _localEndPoint;
            private IPEndPoint _remoteEndPoint;

            private IPAddress GetIPAddress()
            {
                switch (_remote.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        return IPAddress.Any;
                    case AddressFamily.InterNetworkV6:
                        return IPAddress.IPv6Any;
                    default:
                        return IPAddress.Any;
                }
            }

            public UDPHandler(Socket local, Server server, IPEndPoint localEndPoint)
            {
                _local = local;
                _server = server;
                _localEndPoint = localEndPoint;

                // TODO async resolving
                IPAddress ipAddress;
                bool parsed = IPAddress.TryParse(server.server, out ipAddress);
                if (!parsed)
                {
                    IPHostEntry ipHostInfo = Dns.GetHostEntry(server.server);
                    ipAddress = ipHostInfo.AddressList[0];
                }
                _remoteEndPoint = new IPEndPoint(ipAddress, server.server_port);
                _remote = new Socket(_remoteEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                _remote.Bind(new IPEndPoint(GetIPAddress(), 0));

                _encryptor = EncryptorFactory.GetEncryptor(server.method, server.password);
            }

            public void Send(byte[] data, int length)
            {
                byte[] dataIn = new byte[length - 3];
                Array.Copy(data, 3, dataIn, 0, length - 3);
                byte[] dataOut = new byte[65536];  // enough space for AEAD ciphers
                int outlen;
                try
                {
                    _encryptor.EncryptUDP(dataIn, length - 3, dataOut, out outlen);
                }
                catch (CryptoErrorException e)
                {
                    // Drop the datagram rather than the session: UDP is lossy
                    // anyway, and the next packet may well be fine.
                    logger.Warn($"UDP encryption failed, dropping the packet: {e.Message}");
                    return;
                }
                logger.Debug(_localEndPoint, _remoteEndPoint, outlen, "UDP Relay");
                _remote?.SendTo(dataOut, outlen, SocketFlags.None, _remoteEndPoint);
            }

            public void Receive()
            {
                EndPoint remoteEndPoint = new IPEndPoint(GetIPAddress(), 0);
                logger.Debug($"++++++Receive Server Port, size:" + _buffer.Length);
                _remote?.BeginReceiveFrom(_buffer, 0, _buffer.Length, 0, ref remoteEndPoint, new AsyncCallback(RecvFromCallback), null);
            }

            public void RecvFromCallback(IAsyncResult ar)
            {
                bool disposed = false;
                try
                {
                    if (_remote == null) return;
                    EndPoint remoteEndPoint = new IPEndPoint(GetIPAddress(), 0);
                    int bytesRead = _remote.EndReceiveFrom(ar, ref remoteEndPoint);

                    byte[] dataOut = new byte[bytesRead];
                    int outlen;

                    _encryptor.DecryptUDP(_buffer, bytesRead, dataOut, out outlen);

                    byte[] sendBuf = new byte[outlen + 3];
                    Array.Copy(dataOut, 0, sendBuf, 3, outlen);

                    logger.Debug(_localEndPoint, _remoteEndPoint, outlen, "UDP Relay");
                    _local?.SendTo(sendBuf, outlen + 3, 0, _localEndPoint);
                }
                catch (ObjectDisposedException)
                {
                    disposed = true;
                }
                catch (CryptoErrorException e)
                {
                    // A packet that fails to authenticate, repeats a packet id
                    // or arrives too late is exactly what the 2022 methods are
                    // meant to refuse. Drop it and carry on.
                    logger.Debug($"Dropping a UDP packet: {e.Message}");
                }
                catch (Exception e)
                {
                    logger.LogUsefulException(e);
                }
                finally
                {
                    // Re-arm unconditionally. This used to sit at the end of the
                    // try block, so any failure above -- a rejected packet
                    // included -- left the handler deaf for the rest of its life.
                    if (!disposed)
                    {
                        try
                        {
                            Receive();
                        }
                        catch (ObjectDisposedException)
                        {
                        }
                    }
                }
            }

            public void Close()
            {
                try
                {
                    _remote?.Close();
                }
                catch (ObjectDisposedException)
                {
                    // TODO: handle the ObjectDisposedException
                }
                catch (Exception)
                {
                    // TODO: need more think about handle other Exceptions, or should remove this catch().
                }

                // The handler owns the encryptor now, and the LRU cache closes
                // whatever it evicts, so this is where the native contexts go.
                try
                {
                    _encryptor?.Dispose();
                }
                catch (Exception e)
                {
                    logger.LogUsefulException(e);
                }
            }
        }
    }

    #region LRU cache

    // cc by-sa 3.0 http://stackoverflow.com/a/3719378/1124054
    class LRUCache<K, V> where V : UDPRelay.UDPHandler
    {
        private int capacity;
        private Dictionary<K, LinkedListNode<LRUCacheItem<K, V>>> cacheMap = new Dictionary<K, LinkedListNode<LRUCacheItem<K, V>>>();
        private LinkedList<LRUCacheItem<K, V>> lruList = new LinkedList<LRUCacheItem<K, V>>();

        public LRUCache(int capacity)
        {
            this.capacity = capacity;
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public V get(K key)
        {
            LinkedListNode<LRUCacheItem<K, V>> node;
            if (cacheMap.TryGetValue(key, out node))
            {
                V value = node.Value.value;
                lruList.Remove(node);
                lruList.AddLast(node);
                return value;
            }
            return default(V);
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public void add(K key, V val)
        {
            if (cacheMap.Count >= capacity)
            {
                RemoveFirst();
            }

            LRUCacheItem<K, V> cacheItem = new LRUCacheItem<K, V>(key, val);
            LinkedListNode<LRUCacheItem<K, V>> node = new LinkedListNode<LRUCacheItem<K, V>>(cacheItem);
            lruList.AddLast(node);
            cacheMap.Add(key, node);
        }

        private void RemoveFirst()
        {
            // Remove from LRUPriority
            LinkedListNode<LRUCacheItem<K, V>> node = lruList.First;
            lruList.RemoveFirst();

            // Remove from cache
            cacheMap.Remove(node.Value.key);
            node.Value.value.Close();
        }
    }

    class LRUCacheItem<K, V>
    {
        public LRUCacheItem(K k, V v)
        {
            key = k;
            value = v;
        }
        public K key;
        public V value;
    }

    #endregion
}
