using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using NLog;
using Shadowsocks.Controller;
using Shadowsocks.Encryption.CircularBuffer;
using Shadowsocks.Encryption.Exception;

namespace Shadowsocks.Encryption.AEAD
{
    /// <summary>
    /// SIP022, the Shadowsocks 2022 edition: 2022-blake3-aes-128-gcm,
    /// 2022-blake3-aes-256-gcm and 2022-blake3-chacha20-poly1305.
    ///
    /// It shares only chunk framing and the little-endian nonce counter with
    /// AEAD-2018, so it does not derive from <see cref="AEADEncryptor"/>. What
    /// differs: subkeys come from BLAKE3 rather than HKDF-SHA1, the password is
    /// a base64 key rather than something to run through EVP_BytesToKey, both
    /// directions open with a header, and the response header has to be checked
    /// against the request before any payload is believed.
    ///
    /// UDP is a second construction again, session-based rather than streamed;
    /// it lives in its own region below and shares only the key and the header
    /// validation rules with the stream side.
    /// </summary>
    public class AEAD2022Encryptor : EncryptorBase, IDisposable
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();

        private const int TagSize = AeadCipher.TagSize;
        private const int NonceSize = AeadCipher.NonceSize;
        private const int ChunkLenBytes = 2;
        private const int TimestampSize = 8;

        private const byte HeaderTypeClientStream = 0x00;
        private const byte HeaderTypeServerStream = 0x01;

        // type || timestamp || length
        private const int FixedRequestHeaderSize = 1 + TimestampSize + ChunkLenBytes;

        private const long MaxTimestampSkewSeconds = 30;
        private const int MaxPaddingSize = 900;

        /// <summary>
        /// SIP022 raises the chunk payload cap to 0xFFFF, where AEAD-2018 stops
        /// at 0x3FFF, so a conforming server may send us a chunk this large.
        /// </summary>
        public const int MaxChunkRecvSize = 0xFFFF;

        /// <summary>
        /// What we send. 0x3FFF is always valid and keeps the encrypt-side
        /// output well inside the relay's send buffer; there is nothing to gain
        /// from larger chunks when a read never gives us more than RecvSize.
        /// </summary>
        private const int MaxChunkSendSize = 0x3FFF;

        /// <summary>
        /// Enough for one whole framed 0xFFFF chunk plus the read that completes
        /// it. ByteCircularBuffer.Put throws rather than growing, and a chunk
        /// cannot be decrypted until all of it has arrived.
        /// </summary>
        public const int RecvBufferCapacity =
            ChunkLenBytes + TagSize + MaxChunkRecvSize + TagSize + TCPHandler.RecvSize;

        private sealed class CipherInfo
        {
            public readonly int KeySize;
            public readonly string OpenSslName;

            /// <summary>
            /// The two AES methods share one UDP construction and the chacha
            /// method has its own; nothing about TCP depends on this.
            /// </summary>
            public readonly bool IsAes;

            public CipherInfo(int keySize, string openSslName, bool isAes)
            {
                KeySize = keySize;
                OpenSslName = openSslName;
                IsAes = isAes;
            }
        }

        private static readonly Dictionary<string, CipherInfo> _ciphers =
            new Dictionary<string, CipherInfo>
            {
                { "2022-blake3-aes-128-gcm", new CipherInfo(16, "aes-128-gcm", true) },
                { "2022-blake3-aes-256-gcm", new CipherInfo(32, "aes-256-gcm", true) },
                { "2022-blake3-chacha20-poly1305", new CipherInfo(32, "chacha20-poly1305", false) },
            };

        public static List<string> SupportedCiphers()
        {
            return new List<string>(_ciphers.Keys);
        }

        private readonly CipherInfo _info;
        private readonly byte[] _psk;

        // Salt length equals key length for all three methods.
        private readonly int _keyLen;

        // Stream framing only, and together they come to about 130 KB. A UDP
        // handler holds its encryptor for the life of the session without ever
        // touching these, and the relay caches hundreds of handlers, so they
        // are built on first use rather than in the constructor.
        private ByteCircularBuffer _encCircularBuffer;
        private ByteCircularBuffer _decCircularBuffer;

        private readonly byte[] _encNonce = new byte[NonceSize];
        private readonly byte[] _decNonce = new byte[NonceSize];

        private AeadCipher _encCipher;
        private AeadCipher _decCipher;

        private byte[] _encSalt;
        private bool _requestHeaderSent;

        private bool _decCipherReady;
        private bool _responseHeaderRead;
        private bool _firstResponseChunkPending;
        private int _firstResponseChunkLen;

        // Length of the chunk currently being assembled, once its header has
        // been opened, or -1 while there is no chunk in flight. Opening that
        // header is not a commitment -- the nonce may not advance until the
        // whole payload is in hand -- so without somewhere to keep the result,
        // every read that fell short re-opened the same 18 bytes.
        private int _pendingChunkLen = -1;

        public AEAD2022Encryptor(string method, string password)
            : base(method, password)
        {
            _info = _ciphers[method.ToLowerInvariant()];
            _keyLen = _info.KeySize;
            _psk = ParsePreSharedKey(password, _keyLen, method);
        }

        /// <summary>
        /// Throws unless <paramref name="password"/> is the base64 key that
        /// <paramref name="method"/> needs; a no-op for every other method.
        /// Called while validating a server so a bad key is refused in the
        /// dialog rather than becoming a connection that never authenticates.
        /// </summary>
        public static void CheckKey(string method, string password)
        {
            if (method == null)
            {
                return;
            }

            CipherInfo info;
            if (!_ciphers.TryGetValue(method.ToLowerInvariant(), out info))
            {
                return;
            }

            ParsePreSharedKey(password, info.KeySize, method);
        }

        /// <summary>
        /// The password field is base64 of the raw key, not something to stretch.
        /// Rejecting a bad one here means the failure names itself instead of
        /// surfacing as a connection that never authenticates.
        /// </summary>
        private static byte[] ParsePreSharedKey(string password, int keyLen, string method)
        {
            if (password == null)
            {
                password = string.Empty;
            }

            if (password.Contains(":"))
            {
                throw new CryptoErrorException(
                    $"{method}: multi-user keys (extensible identity headers) are not supported");
            }

            byte[] psk;
            try
            {
                psk = Convert.FromBase64String(password);
            }
            catch (FormatException)
            {
                throw new CryptoErrorException(
                    $"{method}: the password must be a base64-encoded {keyLen}-byte key, " +
                    $"as produced by `openssl rand -base64 {keyLen}`");
            }

            if (psk.Length != keyLen)
            {
                throw new CryptoErrorException(
                    $"{method}: the key must be exactly {keyLen} bytes, but the password decodes to {psk.Length}");
            }

            return psk;
        }

        private static void IncrementNonce(byte[] nonce)
        {
            Sodium.sodium_increment(nonce, (UIntPtr)(uint)NonceSize);
        }

        private static void WriteUInt16BE(byte[] buf, int offset, int value)
        {
            buf[offset] = (byte)(value >> 8);
            buf[offset + 1] = (byte)value;
        }

        private static int ReadUInt16BE(byte[] buf, int offset)
        {
            return (buf[offset] << 8) | buf[offset + 1];
        }

        private static void WriteUInt64BE(byte[] buf, int offset, ulong value)
        {
            for (int i = 7; i >= 0; i--)
            {
                buf[offset + i] = (byte)value;
                value >>= 8;
            }
        }

        private static long ReadInt64BE(byte[] buf, int offset)
        {
            return (long)ReadUInt64BE(buf, offset);
        }

        private static ulong ReadUInt64BE(byte[] buf, int offset)
        {
            ulong value = 0;
            for (int i = 0; i < 8; i++)
            {
                value = (value << 8) | buf[offset + i];
            }
            return value;
        }

        #region TCP

        public override void Encrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            if (_encCircularBuffer == null)
            {
                _encCircularBuffer = new ByteCircularBuffer(MAX_INPUT_SIZE * 2);
            }
            _encCircularBuffer.Put(buf, 0, length);
            outlength = 0;

            if (!_requestHeaderSent)
            {
                // Only after it has actually gone out: the chunk loop below
                // dereferences _encCipher, which the header sets up.
                WriteRequestHeader(outbuf, ref outlength);
                _requestHeaderSent = true;
            }

            while (_encCircularBuffer.Size > 0)
            {
                int chunkLen = Math.Min(_encCircularBuffer.Size, MaxChunkSendSize);
                int framedLen = ChunkLenBytes + TagSize + chunkLen + TagSize;
                if (outlength + framedLen > outbuf.Length)
                {
                    // Whatever is left stays buffered for the next call. Cannot
                    // happen while a read is capped at RecvSize, but the buffer
                    // arithmetic should not depend on that.
                    logger.Trace("enc outbuf full, leaving the rest buffered");
                    return;
                }

                byte[] lenBytes = new byte[ChunkLenBytes];
                WriteUInt16BE(lenBytes, 0, chunkLen);
                _encCipher.Seal(_encNonce, lenBytes, ChunkLenBytes, outbuf, outlength);
                IncrementNonce(_encNonce);
                outlength += ChunkLenBytes + TagSize;

                byte[] chunk = _encCircularBuffer.Get(chunkLen);
                _encCipher.Seal(_encNonce, chunk, chunkLen, outbuf, outlength);
                IncrementNonce(_encNonce);
                outlength += chunkLen + TagSize;
            }
        }

        /// <summary>
        /// salt || sealed fixed-length header || sealed variable-length header.
        /// The caller hands us the SOCKS5 address as the first AddrBufLength
        /// bytes of the stream, exactly the form the header wants.
        /// </summary>
        private void WriteRequestHeader(byte[] outbuf, ref int outlength)
        {
            if (AddrBufLength <= 0)
            {
                throw new CryptoErrorException("2022: the target address is not known yet");
            }

            _encSalt = new byte[_keyLen];
            RNG.GetBytes(_encSalt, _keyLen);

            byte[] subkey = new byte[_keyLen];
            Blake3.DeriveSessionSubkey(_psk, _encSalt, subkey);
            _encCipher = new AeadCipher(_info.OpenSslName, subkey, true);

            byte[] address = _encCircularBuffer.Get(AddrBufLength);

            // As much of what we already hold as fits; the rest goes out as
            // ordinary chunks.
            int room = MaxChunkSendSize - AddrBufLength - ChunkLenBytes;
            int payloadLen = Math.Max(0, Math.Min(_encCircularBuffer.Size, room));

            // "Either initial payload or padding MUST be present."
            int padLen = payloadLen > 0 ? 0 : RandomPaddingLength();

            byte[] varHeader = new byte[AddrBufLength + ChunkLenBytes + padLen + payloadLen];
            int pos = 0;
            Buffer.BlockCopy(address, 0, varHeader, pos, AddrBufLength);
            pos += AddrBufLength;
            WriteUInt16BE(varHeader, pos, padLen);
            pos += ChunkLenBytes;
            if (padLen > 0)
            {
                byte[] padding = new byte[padLen];
                RNG.GetBytes(padding, padLen);
                Buffer.BlockCopy(padding, 0, varHeader, pos, padLen);
                pos += padLen;
            }
            if (payloadLen > 0)
            {
                byte[] payload = _encCircularBuffer.Get(payloadLen);
                Buffer.BlockCopy(payload, 0, varHeader, pos, payloadLen);
            }

            byte[] fixedHeader = new byte[FixedRequestHeaderSize];
            fixedHeader[0] = HeaderTypeClientStream;
            WriteUInt64BE(fixedHeader, 1, (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            WriteUInt16BE(fixedHeader, 1 + TimestampSize, varHeader.Length);

            Buffer.BlockCopy(_encSalt, 0, outbuf, 0, _keyLen);
            outlength = _keyLen;

            _encCipher.Seal(_encNonce, fixedHeader, FixedRequestHeaderSize, outbuf, outlength);
            IncrementNonce(_encNonce);
            outlength += FixedRequestHeaderSize + TagSize;

            _encCipher.Seal(_encNonce, varHeader, varHeader.Length, outbuf, outlength);
            IncrementNonce(_encNonce);
            outlength += varHeader.Length + TagSize;

            logger.Trace($"2022 request header sent, {outlength} bytes, padding {padLen}");
        }

        private static int RandomPaddingLength()
        {
            byte[] rand = new byte[2];
            RNG.GetBytes(rand, 2);
            // 1..MaxPaddingSize: the padding has to be non-empty when there is
            // no initial payload to hide the request behind.
            return (((rand[0] << 8) | rand[1]) % MaxPaddingSize) + 1;
        }

        public override void Decrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            if (_decCircularBuffer == null)
            {
                _decCircularBuffer = new ByteCircularBuffer(RecvBufferCapacity);
            }
            _decCircularBuffer.Put(buf, 0, length);
            outlength = 0;

            if (!_decCipherReady)
            {
                if (_decCircularBuffer.Size < _keyLen)
                {
                    return;
                }

                byte[] salt = _decCircularBuffer.Get(_keyLen);
                byte[] subkey = new byte[_keyLen];
                Blake3.DeriveSessionSubkey(_psk, salt, subkey);
                _decCipher = new AeadCipher(_info.OpenSslName, subkey, false);
                _decCipherReady = true;
            }

            if (!_responseHeaderRead && !ReadResponseHeader())
            {
                return;
            }

            if (_firstResponseChunkPending)
            {
                if (_decCircularBuffer.Size < _firstResponseChunkLen + TagSize)
                {
                    return;
                }

                byte[] sealedChunk = _decCircularBuffer.Get(_firstResponseChunkLen + TagSize);
                outlength += _decCipher.Open(_decNonce, sealedChunk, sealedChunk.Length, outbuf, outlength);
                IncrementNonce(_decNonce);
                _firstResponseChunkPending = false;
            }

            while (true)
            {
                if (_pendingChunkLen < 0)
                {
                    if (_decCircularBuffer.Size <= ChunkLenBytes + TagSize)
                    {
                        return;
                    }

                    // Peeked, not consumed: the payload may not have arrived
                    // yet, and the nonce must not move until we commit to the
                    // chunk. The length is kept so that a chunk spread over
                    // several reads is not re-opened once per read.
                    byte[] sealedLen = _decCircularBuffer.Peek(ChunkLenBytes + TagSize);
                    byte[] lenBytes = new byte[ChunkLenBytes];
                    _decCipher.Open(_decNonce, sealedLen, sealedLen.Length, lenBytes, 0);
                    _pendingChunkLen = ReadUInt16BE(lenBytes, 0);
                }

                int chunkLen = _pendingChunkLen;
                if (_decCircularBuffer.Size < ChunkLenBytes + TagSize + chunkLen + TagSize)
                {
                    logger.Trace("not enough data for one chunk yet");
                    return;
                }
                if (outlength + chunkLen > outbuf.Length)
                {
                    logger.Trace("dec outbuf full, leaving the rest buffered");
                    return;
                }

                IncrementNonce(_decNonce);
                _decCircularBuffer.Skip(ChunkLenBytes + TagSize);
                _pendingChunkLen = -1;

                byte[] sealedChunk = _decCircularBuffer.Get(chunkLen + TagSize);
                outlength += _decCipher.Open(_decNonce, sealedChunk, sealedChunk.Length, outbuf, outlength);
                IncrementNonce(_decNonce);
            }
        }

        /// <summary>
        /// type || timestamp || request salt || length. Returns false while the
        /// header is still incomplete.
        /// </summary>
        private bool ReadResponseHeader()
        {
            int headerLen = 1 + TimestampSize + _keyLen + ChunkLenBytes;
            if (_decCircularBuffer.Size < headerLen + TagSize)
            {
                return false;
            }

            byte[] sealedHeader = _decCircularBuffer.Get(headerLen + TagSize);
            byte[] header = new byte[headerLen];
            _decCipher.Open(_decNonce, sealedHeader, sealedHeader.Length, header, 0);
            IncrementNonce(_decNonce);

            if (header[0] != HeaderTypeServerStream)
            {
                throw new CryptoErrorException($"2022: response header type is {header[0]}, expected 1");
            }

            long timestamp = ReadInt64BE(header, 1);
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long skew = Math.Abs(now - timestamp);
            if (skew > MaxTimestampSkewSeconds)
            {
                throw new CryptoErrorException(
                    $"2022: response timestamp is {skew}s away from now, treating it as a replay");
            }

            if (_encSalt == null)
            {
                throw new CryptoErrorException("2022: the server replied before the request was sent");
            }
            for (int i = 0; i < _keyLen; i++)
            {
                if (header[1 + TimestampSize + i] != _encSalt[i])
                {
                    throw new CryptoErrorException("2022: response does not echo the request salt");
                }
            }

            _firstResponseChunkLen = ReadUInt16BE(header, 1 + TimestampSize + _keyLen);
            _responseHeaderRead = true;
            _firstResponseChunkPending = true;
            logger.Trace($"2022 response header read, first chunk {_firstResponseChunkLen} bytes");
            return true;
        }

        #endregion

        #region UDP

        // SIP022 UDP is a separate construction from the stream above: each
        // packet stands alone, keyed by a session id rather than a salt, with a
        // monotonic packet id in place of the nonce counter and a replay window
        // instead of ordering. The two families differ again -- the AES methods
        // put the session and packet ids in a 16-byte header encrypted with the
        // PSK as a raw AES block, while the chacha method carries them inside
        // the body and seals the lot with XChaCha20-Poly1305 under the PSK.
        //
        // One lock covers all of it: Send and the receive callback run on
        // different threads, and they share the client session id, the AES-ECB
        // transforms and the server session table.
        private readonly object _udpLock = new object();

        private const int UdpSessionIdSize = 8;
        private const int UdpPacketIdSize = 8;
        private const int UdpSeparateHeaderSize = UdpSessionIdSize + UdpPacketIdSize;
        private const int PaddingLenBytes = 2;
        private const int XChaChaNonceSize = 24;

        private const byte HeaderTypeClientPacket = 0x00;
        private const byte HeaderTypeServerPacket = 0x01;

        // Body prefix ahead of the padding, client to server.
        private const int UdpClientHeaderSize = 1 + TimestampSize + PaddingLenBytes;
        // Same, server to client: it also echoes our session id.
        private const int UdpServerHeaderSize =
            1 + TimestampSize + UdpSessionIdSize + PaddingLenBytes;

        // The chacha method has no separate header, so both bodies are preceded
        // by the session and packet ids instead.
        private const int UdpInlineIdsSize = UdpSessionIdSize + UdpPacketIdSize;

        private byte[] _udpClientSessionId;
        private ulong _udpClientPacketId;
        private AeadCipher _udpEncCipher;
        private Aes _udpEcb;
        private ICryptoTransform _udpEcbEncrypt;
        private ICryptoTransform _udpEcbDecrypt;

        /// <summary>
        /// One of the server's sessions. SIP022 lets a server answer from a new
        /// session at any time, and requires a client to keep at least the
        /// current one and the one before it.
        /// </summary>
        private sealed class ServerSession
        {
            public readonly ulong SessionId;
            // null for the chacha method, which keys every packet off the PSK.
            public readonly AeadCipher Cipher;
            public readonly SlidingWindow Window = new SlidingWindow();

            public ServerSession(ulong sessionId, AeadCipher cipher)
            {
                SessionId = sessionId;
                Cipher = cipher;
            }
        }

        private ServerSession _udpServerSession;
        private ServerSession _udpPreviousServerSession;

        public override void EncryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            lock (_udpLock)
            {
                EnsureUdpClientSession();
                outlength = _info.IsAes
                    ? EncryptUdpAes(buf, length, outbuf)
                    : EncryptUdpXChaCha(buf, length, outbuf);
            }
        }

        public override void DecryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            lock (_udpLock)
            {
                if (_udpClientSessionId == null)
                {
                    throw new CryptoErrorException("2022: a UDP reply arrived before anything was sent");
                }
                outlength = _info.IsAes
                    ? DecryptUdpAes(buf, length, outbuf)
                    : DecryptUdpXChaCha(buf, length, outbuf);
            }
        }

        private void EnsureUdpClientSession()
        {
            if (_udpClientSessionId != null)
            {
                return;
            }

            _udpClientSessionId = new byte[UdpSessionIdSize];
            RNG.GetBytes(_udpClientSessionId, UdpSessionIdSize);

            if (!_info.IsAes)
            {
                // XChaCha20-Poly1305 straight off the PSK: nothing to set up.
                return;
            }

            byte[] subkey = new byte[_keyLen];
            Blake3.DeriveSessionSubkey(_psk, _udpClientSessionId, subkey);
            _udpEncCipher = new AeadCipher(_info.OpenSslName, subkey, true);

            _udpEcb = Aes.Create();
            _udpEcb.Mode = CipherMode.ECB;
            _udpEcb.Padding = PaddingMode.None;
            _udpEcb.Key = _psk;
            _udpEcbEncrypt = _udpEcb.CreateEncryptor();
            _udpEcbDecrypt = _udpEcb.CreateDecryptor();
        }

        /// <summary>
        /// type || timestamp || padding length || padding || the caller's bytes.
        /// The caller hands us a SOCKS5 address followed by the payload, which
        /// is the order the header wants them in, so they go in untouched.
        /// </summary>
        private void WriteUdpClientBody(byte[] body, int offset, byte[] buf, int length)
        {
            body[offset] = HeaderTypeClientPacket;
            WriteUInt64BE(body, offset + 1, (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            // No padding: SIP022 permits it on UDP but does not ask for it, and
            // a length of zero keeps the packet the size the caller expects.
            WriteUInt16BE(body, offset + 1 + TimestampSize, 0);
            Buffer.BlockCopy(buf, 0, body, offset + UdpClientHeaderSize, length);
        }

        private int EncryptUdpAes(byte[] buf, int length, byte[] outbuf)
        {
            int bodyLen = UdpClientHeaderSize + length;
            int packetLen = UdpSeparateHeaderSize + bodyLen + TagSize;
            if (packetLen > outbuf.Length)
            {
                throw new CryptoErrorException("2022: UDP packet does not fit the output buffer");
            }

            byte[] separateHeader = new byte[UdpSeparateHeaderSize];
            Buffer.BlockCopy(_udpClientSessionId, 0, separateHeader, 0, UdpSessionIdSize);
            WriteUInt64BE(separateHeader, UdpSessionIdSize, _udpClientPacketId++);

            // The nonce comes out of the plaintext separate header, not the
            // encrypted one the server sees first.
            byte[] nonce = new byte[NonceSize];
            Buffer.BlockCopy(separateHeader, UdpSeparateHeaderSize - NonceSize, nonce, 0, NonceSize);

            byte[] body = new byte[bodyLen];
            WriteUdpClientBody(body, 0, buf, length);

            _udpEcbEncrypt.TransformBlock(separateHeader, 0, UdpSeparateHeaderSize, outbuf, 0);
            _udpEncCipher.Seal(nonce, body, bodyLen, outbuf, UdpSeparateHeaderSize);
            return packetLen;
        }

        private int EncryptUdpXChaCha(byte[] buf, int length, byte[] outbuf)
        {
            int bodyLen = UdpInlineIdsSize + UdpClientHeaderSize + length;
            int packetLen = XChaChaNonceSize + bodyLen + TagSize;
            if (packetLen > outbuf.Length)
            {
                throw new CryptoErrorException("2022: UDP packet does not fit the output buffer");
            }

            byte[] nonce = new byte[XChaChaNonceSize];
            RNG.GetBytes(nonce, XChaChaNonceSize);

            byte[] body = new byte[bodyLen];
            Buffer.BlockCopy(_udpClientSessionId, 0, body, 0, UdpSessionIdSize);
            WriteUInt64BE(body, UdpSessionIdSize, _udpClientPacketId++);
            WriteUdpClientBody(body, UdpInlineIdsSize, buf, length);

            byte[] sealedBody = new byte[bodyLen + TagSize];
            ulong sealedLen = 0;
            int ret = Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                sealedBody, ref sealedLen,
                body, (ulong)bodyLen,
                null, 0,
                null, nonce,
                _psk);
            if (ret != 0)
            {
                throw new CryptoErrorException($"2022: xchacha20-poly1305 seal failed, ret {ret}");
            }

            Buffer.BlockCopy(nonce, 0, outbuf, 0, XChaChaNonceSize);
            Buffer.BlockCopy(sealedBody, 0, outbuf, XChaChaNonceSize, (int)sealedLen);
            return XChaChaNonceSize + (int)sealedLen;
        }

        private int DecryptUdpAes(byte[] buf, int length, byte[] outbuf)
        {
            if (length < UdpSeparateHeaderSize + TagSize)
            {
                throw new CryptoErrorException("2022: UDP packet is too short to hold a header");
            }

            byte[] separateHeader = new byte[UdpSeparateHeaderSize];
            _udpEcbDecrypt.TransformBlock(buf, 0, UdpSeparateHeaderSize, separateHeader, 0);

            byte[] sessionIdBytes = new byte[UdpSessionIdSize];
            Buffer.BlockCopy(separateHeader, 0, sessionIdBytes, 0, UdpSessionIdSize);
            ulong packetId = ReadUInt64BE(separateHeader, UdpSessionIdSize);

            // The separate header is only ECB-encrypted, never authenticated, so
            // nothing it says may change our state until the body opens.
            ServerSession known = FindServerSession(ReadUInt64BE(separateHeader, 0));
            ServerSession candidate = known
                ?? CreateServerSession(ReadUInt64BE(separateHeader, 0), sessionIdBytes);
            try
            {
                byte[] nonce = new byte[NonceSize];
                Buffer.BlockCopy(separateHeader, UdpSeparateHeaderSize - NonceSize, nonce, 0, NonceSize);

                int sealedLen = length - UdpSeparateHeaderSize;
                byte[] sealedBody = new byte[sealedLen];
                Buffer.BlockCopy(buf, UdpSeparateHeaderSize, sealedBody, 0, sealedLen);

                byte[] body = new byte[sealedLen - TagSize];
                int bodyLen = candidate.Cipher.Open(nonce, sealedBody, sealedLen, body, 0);

                int outlength = UnwrapUdpServerBody(body, bodyLen, 0, packetId, candidate, outbuf);
                if (known == null)
                {
                    CommitServerSession(candidate);
                    candidate = null;
                }
                return outlength;
            }
            finally
            {
                // Still uncommitted here means the packet was refused.
                if (known == null)
                {
                    candidate?.Cipher?.Dispose();
                }
            }
        }

        private int DecryptUdpXChaCha(byte[] buf, int length, byte[] outbuf)
        {
            if (length < XChaChaNonceSize + UdpInlineIdsSize + TagSize)
            {
                throw new CryptoErrorException("2022: UDP packet is too short to hold a header");
            }

            byte[] nonce = new byte[XChaChaNonceSize];
            Buffer.BlockCopy(buf, 0, nonce, 0, XChaChaNonceSize);

            int sealedLen = length - XChaChaNonceSize;
            byte[] sealedBody = new byte[sealedLen];
            Buffer.BlockCopy(buf, XChaChaNonceSize, sealedBody, 0, sealedLen);

            byte[] body = new byte[sealedLen - TagSize];
            ulong bodyLen = 0;
            int ret = Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                body, ref bodyLen,
                null,
                sealedBody, (ulong)sealedLen,
                null, 0,
                nonce, _psk);
            if (ret != 0)
            {
                throw new CryptoErrorException($"2022: xchacha20-poly1305 open failed, ret {ret}");
            }

            // Here the ids come out of an already-authenticated body, but the
            // session table still only moves once the header checks out.
            ulong serverSessionId = ReadUInt64BE(body, 0);
            ulong packetId = ReadUInt64BE(body, UdpSessionIdSize);

            ServerSession known = FindServerSession(serverSessionId);
            ServerSession candidate = known ?? CreateServerSession(serverSessionId, null);

            int outlength = UnwrapUdpServerBody(body, (int)bodyLen, UdpInlineIdsSize, packetId,
                candidate, outbuf);
            if (known == null)
            {
                CommitServerSession(candidate);
            }
            return outlength;
        }

        /// <summary>
        /// Validates the server's message header and copies out what follows it,
        /// which is already the SOCKS5 address plus payload the relay wants.
        /// </summary>
        private int UnwrapUdpServerBody(byte[] body, int bodyLen, int offset, ulong packetId,
            ServerSession session, byte[] outbuf)
        {
            if (bodyLen - offset < UdpServerHeaderSize)
            {
                throw new CryptoErrorException("2022: UDP reply header is truncated");
            }

            if (body[offset] != HeaderTypeServerPacket)
            {
                throw new CryptoErrorException(
                    $"2022: UDP reply header type is {body[offset]}, expected 1");
            }

            long timestamp = ReadInt64BE(body, offset + 1);
            long skew = Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp);
            if (skew > MaxTimestampSkewSeconds)
            {
                throw new CryptoErrorException(
                    $"2022: UDP reply timestamp is {skew}s away from now, treating it as a replay");
            }

            int echoOffset = offset + 1 + TimestampSize;
            for (int i = 0; i < UdpSessionIdSize; i++)
            {
                if (body[echoOffset + i] != _udpClientSessionId[i])
                {
                    throw new CryptoErrorException("2022: UDP reply is for another client session");
                }
            }

            int padLen = ReadUInt16BE(body, echoOffset + UdpSessionIdSize);
            int payloadOffset = offset + UdpServerHeaderSize + padLen;
            if (payloadOffset > bodyLen)
            {
                throw new CryptoErrorException("2022: UDP reply padding runs past the packet");
            }

            // Only now, with the header believed: SIP022 says the window moves
            // on validated packets, so a forged id cannot push it forward.
            if (!session.Window.TryAccept(packetId))
            {
                throw new CryptoErrorException($"2022: UDP packet id {packetId} is a replay or too old");
            }

            int payloadLen = bodyLen - payloadOffset;
            if (payloadLen > outbuf.Length)
            {
                throw new CryptoErrorException("2022: UDP reply does not fit the output buffer");
            }
            Buffer.BlockCopy(body, payloadOffset, outbuf, 0, payloadLen);
            return payloadLen;
        }

        private ServerSession FindServerSession(ulong sessionId)
        {
            if (_udpServerSession != null && _udpServerSession.SessionId == sessionId)
            {
                return _udpServerSession;
            }
            if (_udpPreviousServerSession != null && _udpPreviousServerSession.SessionId == sessionId)
            {
                return _udpPreviousServerSession;
            }
            return null;
        }

        /// <summary>
        /// Builds a session without recording it. The caller records it only
        /// once a packet from it has actually been believed.
        /// </summary>
        private ServerSession CreateServerSession(ulong sessionId, byte[] sessionIdBytes)
        {
            AeadCipher cipher = null;
            if (_info.IsAes)
            {
                byte[] subkey = new byte[_keyLen];
                Blake3.DeriveSessionSubkey(_psk, sessionIdBytes, subkey);
                cipher = new AeadCipher(_info.OpenSslName, subkey, false);
            }
            return new ServerSession(sessionId, cipher);
        }

        private void CommitServerSession(ServerSession session)
        {
            // Keep the current one and the one before it, which is the least
            // SIP022 allows a client to remember; the third oldest is dropped.
            _udpPreviousServerSession?.Cipher?.Dispose();
            _udpPreviousServerSession = _udpServerSession;
            _udpServerSession = session;
            logger.Debug($"2022: tracking UDP server session {session.SessionId:x16}");
        }

        private void DisposeUdp()
        {
            _udpEncCipher?.Dispose();
            _udpEncCipher = null;
            _udpServerSession?.Cipher?.Dispose();
            _udpServerSession = null;
            _udpPreviousServerSession?.Cipher?.Dispose();
            _udpPreviousServerSession = null;
            _udpEcbEncrypt?.Dispose();
            _udpEcbEncrypt = null;
            _udpEcbDecrypt?.Dispose();
            _udpEcbDecrypt = null;
            _udpEcb?.Dispose();
            _udpEcb = null;
        }

        #endregion

        public override void Dispose()
        {
            _encCipher?.Dispose();
            _encCipher = null;
            _decCipher?.Dispose();
            _decCipher = null;
            lock (_udpLock)
            {
                DisposeUdp();
            }
        }
    }
}
