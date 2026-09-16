using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using NLog;
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

        // The cache only evicts when it is full, so an idle handler -- and the
        // native cipher contexts its encryptor now holds for the life of the
        // session -- used to sit there until a 512th endpoint came along, or
        // until the process exited. Five minutes is well past any NAT's idea of
        // a UDP mapping, and the sweep is throttled the way TCPRelay throttles
        // its own, since Handle runs once per datagram rather than per session.
        private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(1);

        private readonly object _sweepLock = new object();
        private DateTime _lastSweepTime = DateTime.Now;

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
                handler = new UDPHandler(socket, _controller.GetCurrentServer(), remoteEndPoint);
                handler.Receive();
                _cache.add(remoteEndPoint, handler);
            }
            handler.Send(firstPacket, length);

            // After the send, so the endpoint we were just asked about is not a
            // candidate for its own sweep.
            SweepIdleHandlers();
            return true;
        }

        public override void Stop()
        {
            _cache.clear();
        }

        private void SweepIdleHandlers()
        {
            lock (_sweepLock)
            {
                DateTime now = DateTime.Now;
                if (now - _lastSweepTime < SweepInterval)
                {
                    return;
                }
                _lastSweepTime = now;
            }
            _cache.sweep(IdleTimeout);
        }

        public class UDPHandler
        {
            private static Logger logger = LogManager.GetCurrentClassLogger();
            private static readonly TimeSpan DnsRefreshInterval = TimeSpan.FromMinutes(1);

            private Socket _local;
            private Socket _remote;

            private Server _server;
            private readonly bool _serverIsDomain;
            private readonly object _remoteLock = new object();
            private readonly object _decryptLock = new object();
            private long _nextDnsRefreshTicks;
            private bool _dnsRefreshInProgress;
            private bool _closed;

            // One per handler, not one per datagram: the 2022 methods carry a
            // session id, a packet id counter and a replay window across the
            // packets of a session, and rebuilding it each time would throw all
            // of that away.
            private readonly IEncryptor _encryptor;

            private IPEndPoint _localEndPoint;
            private IPEndPoint _remoteEndPoint;

            private class ReceiveState
            {
                public readonly Socket Socket;
                public readonly byte[] Buffer = new byte[65536];

                public ReceiveState(Socket socket)
                {
                    Socket = socket;
                }
            }

            // Read by the relay's idle sweep, written from both the thread that
            // sends and the one that receives.
            public DateTime lastActivity;

            private static IPAddress GetIPAddress(Socket socket)
            {
                switch (socket.AddressFamily)
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
                lastActivity = DateTime.Now;

                IPAddress ipAddress;
                bool parsed = IPAddress.TryParse(server.server, out ipAddress);
                _serverIsDomain = !parsed;
                if (!parsed)
                {
                    ipAddress = SelectIPAddress(Dns.GetHostAddresses(server.server), null);
                    if (ipAddress == null)
                    {
                        throw new SocketException((int)SocketError.HostNotFound);
                    }
                }
                _remoteEndPoint = new IPEndPoint(ipAddress, server.server_port);
                _remote = new Socket(_remoteEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                _remote.Bind(new IPEndPoint(GetIPAddress(_remote), 0));
                _nextDnsRefreshTicks = DateTime.UtcNow.Add(DnsRefreshInterval).Ticks;

                _encryptor = EncryptorFactory.GetEncryptor(server.method, server.password);
            }

            private static IPAddress SelectIPAddress(IPAddress[] addresses, IPAddress currentAddress)
            {
                foreach (IPAddress address in addresses)
                {
                    if (address.Equals(currentAddress))
                    {
                        return address;
                    }
                }

                foreach (IPAddress address in addresses)
                {
                    if (currentAddress != null && address.AddressFamily == currentAddress.AddressFamily)
                    {
                        return address;
                    }
                }

                foreach (IPAddress address in addresses)
                {
                    if (address.AddressFamily == AddressFamily.InterNetwork ||
                        address.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        return address;
                    }
                }

                return null;
            }

            private void RefreshRemoteEndPointIfNeeded()
            {
                if (!_serverIsDomain || DateTime.UtcNow.Ticks < Volatile.Read(ref _nextDnsRefreshTicks))
                {
                    return;
                }

                lock (_remoteLock)
                {
                    DateTime now = DateTime.UtcNow;
                    if (_closed || _dnsRefreshInProgress || now.Ticks < Volatile.Read(ref _nextDnsRefreshTicks))
                    {
                        return;
                    }

                    _dnsRefreshInProgress = true;
                    Volatile.Write(ref _nextDnsRefreshTicks, now.Add(DnsRefreshInterval).Ticks);
                }

                try
                {
                    Dns.GetHostAddressesAsync(_server.server).ContinueWith(
                        RefreshRemoteEndPoint,
                        TaskScheduler.Default);
                }
                catch (Exception e)
                {
                    lock (_remoteLock)
                    {
                        _dnsRefreshInProgress = false;
                    }
                    logger.Warn(e, $"Failed to refresh UDP server address for {_server.server}");
                }
            }

            private void RefreshRemoteEndPoint(Task<IPAddress[]> task)
            {
                Socket oldSocket = null;
                Socket newSocket = null;
                try
                {
                    if (task.IsCanceled || task.IsFaulted)
                    {
                        Exception error = task.Exception?.GetBaseException();
                        logger.Warn(error, $"Failed to refresh UDP server address for {_server.server}");
                        return;
                    }

                    lock (_remoteLock)
                    {
                        if (_closed)
                        {
                            return;
                        }

                        IPAddress ipAddress = SelectIPAddress(task.Result, _remoteEndPoint.Address);
                        if (ipAddress == null || ipAddress.Equals(_remoteEndPoint.Address))
                        {
                            return;
                        }

                        IPEndPoint newEndPoint = new IPEndPoint(ipAddress, _server.server_port);
                        if (ipAddress.AddressFamily == _remoteEndPoint.AddressFamily)
                        {
                            _remoteEndPoint = newEndPoint;
                            return;
                        }

                        newSocket = new Socket(ipAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                        newSocket.Bind(new IPEndPoint(GetIPAddress(newSocket), 0));
                        oldSocket = _remote;
                        IPEndPoint oldEndPoint = _remoteEndPoint;
                        _remote = newSocket;
                        _remoteEndPoint = newEndPoint;
                        try
                        {
                            Receive(new ReceiveState(newSocket));
                        }
                        catch
                        {
                            _remote = oldSocket;
                            _remoteEndPoint = oldEndPoint;
                            throw;
                        }
                    }

                    newSocket = null;
                    oldSocket?.Close();
                }
                catch (Exception e)
                {
                    logger.Warn(e, $"Failed to apply refreshed UDP server address for {_server.server}");
                    newSocket?.Close();
                }
                finally
                {
                    lock (_remoteLock)
                    {
                        _dnsRefreshInProgress = false;
                    }
                }
            }

            public void Send(byte[] data, int length)
            {
                lastActivity = DateTime.Now;
                RefreshRemoteEndPointIfNeeded();
                int inputLength = length - 3;
                byte[] dataIn = ArrayPool<byte>.Shared.Rent(Math.Max(inputLength, 1));
                byte[] dataOut = ArrayPool<byte>.Shared.Rent(65536);
                try
                {
                    Buffer.BlockCopy(data, 3, dataIn, 0, inputLength);
                    int outlen;
                    try
                    {
                        _encryptor.EncryptUDP(dataIn, inputLength, dataOut, out outlen);
                    }
                    catch (CryptoErrorException e)
                    {
                        // Drop the datagram rather than the session: UDP is lossy
                        // anyway, and the next packet may well be fine.
                        logger.Warn($"UDP encryption failed, dropping the packet: {e.Message}");
                        return;
                    }
                    lock (_remoteLock)
                    {
                        if (_closed)
                        {
                            return;
                        }
                        logger.Debug(_localEndPoint, _remoteEndPoint, outlen, "UDP Relay");
                        _remote.SendTo(dataOut, outlen, SocketFlags.None, _remoteEndPoint);
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(dataIn);
                    ArrayPool<byte>.Shared.Return(dataOut);
                }
            }

            public void Receive()
            {
                lock (_remoteLock)
                {
                    if (_closed)
                    {
                        return;
                    }
                    Receive(new ReceiveState(_remote));
                }
            }

            private void Receive(ReceiveState state)
            {
                EndPoint remoteEndPoint = new IPEndPoint(GetIPAddress(state.Socket), 0);
                logger.Debug($"++++++Receive Server Port, size:" + state.Buffer.Length);
                state.Socket.BeginReceiveFrom(state.Buffer, 0, state.Buffer.Length, 0, ref remoteEndPoint, RecvFromCallback, state);
            }

            public void RecvFromCallback(IAsyncResult ar)
            {
                bool disposed = false;
                byte[] dataOut = null;
                byte[] sendBuf = null;
                try
                {
                    ReceiveState state = (ReceiveState)ar.AsyncState;
                    EndPoint remoteEndPoint = new IPEndPoint(GetIPAddress(state.Socket), 0);
                    int bytesRead = state.Socket.EndReceiveFrom(ar, ref remoteEndPoint);

                    dataOut = ArrayPool<byte>.Shared.Rent(65536);
                    int outlen;
                    lock (_decryptLock)
                    {
                        _encryptor.DecryptUDP(state.Buffer, bytesRead, dataOut, out outlen);
                    }
                    // Only authenticated packets refresh the idle timeout. Moving this
                    // after DecryptUDP prevents unauthenticated traffic from keeping an
                    // otherwise idle UDP handler alive.
                    lastActivity = DateTime.Now;

                    sendBuf = ArrayPool<byte>.Shared.Rent(outlen + 3);
                    sendBuf[0] = 0;
                    sendBuf[1] = 0;
                    sendBuf[2] = 0;
                    Buffer.BlockCopy(dataOut, 0, sendBuf, 3, outlen);

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
                    if (sendBuf != null) ArrayPool<byte>.Shared.Return(sendBuf);
                    if (dataOut != null) ArrayPool<byte>.Shared.Return(dataOut);

                    // Re-arm unconditionally. This used to sit at the end of the
                    // try block, so any failure above -- a rejected packet
                    // included -- left the handler deaf for the rest of its life.
                    if (!disposed)
                    {
                        try
                        {
                            ReceiveState state = (ReceiveState)ar.AsyncState;
                            lock (_remoteLock)
                            {
                                if (!_closed && ReferenceEquals(state.Socket, _remote))
                                {
                                    Receive(state);
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            // Nothing may escape a finally here: this runs on an
                            // IOCP thread, and an exception that leaves a thread
                            // pool thread unhandled kills the process. A handler
                            // that cannot re-arm goes deaf, and the relay's idle
                            // sweep eventually collects it.
                            logger.LogUsefulException(e);
                        }
                    }
                }
            }

            public void Close()
            {
                Socket remote;
                lock (_remoteLock)
                {
                    if (_closed)
                    {
                        return;
                    }
                    _closed = true;
                    remote = _remote;
                    _remote = null;
                }

                try
                {
                    remote?.Close();
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

        /// <summary>
        /// Drops every handler that has neither sent nor received for
        /// <paramref name="idleTimeout"/>. The list is ordered by use, but only
        /// by outbound use -- a handler that is only receiving never touches
        /// it -- so there is no prefix to stop at, and the whole list is walked.
        /// </summary>
        [MethodImpl(MethodImplOptions.Synchronized)]
        public void sweep(TimeSpan idleTimeout)
        {
            DateTime now = DateTime.Now;
            LinkedListNode<LRUCacheItem<K, V>> node = lruList.First;
            while (node != null)
            {
                LinkedListNode<LRUCacheItem<K, V>> next = node.Next;
                if (now - node.Value.value.lastActivity > idleTimeout)
                {
                    Remove(node);
                }
                node = next;
            }
        }

        [MethodImpl(MethodImplOptions.Synchronized)]
        public void clear()
        {
            foreach (LRUCacheItem<K, V> item in lruList)
            {
                item.value.Close();
            }
            lruList.Clear();
            cacheMap.Clear();
        }

        private void RemoveFirst()
        {
            Remove(lruList.First);
        }

        private void Remove(LinkedListNode<LRUCacheItem<K, V>> node)
        {
            // Remove from LRUPriority
            lruList.Remove(node);

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
