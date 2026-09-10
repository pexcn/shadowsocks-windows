using System;
using System.Collections.Generic;
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
    /// TCP only for now; UDP is a separate construction and is not implemented.
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

            public CipherInfo(int keySize, string openSslName)
            {
                KeySize = keySize;
                OpenSslName = openSslName;
            }
        }

        private static readonly Dictionary<string, CipherInfo> _ciphers =
            new Dictionary<string, CipherInfo>
            {
                { "2022-blake3-aes-128-gcm", new CipherInfo(16, "aes-128-gcm") },
                { "2022-blake3-aes-256-gcm", new CipherInfo(32, "aes-256-gcm") },
                { "2022-blake3-chacha20-poly1305", new CipherInfo(32, "chacha20-poly1305") },
            };

        public static List<string> SupportedCiphers()
        {
            return new List<string>(_ciphers.Keys);
        }

        private readonly CipherInfo _info;
        private readonly byte[] _psk;

        // Salt length equals key length for all three methods.
        private readonly int _keyLen;

        private readonly ByteCircularBuffer _encCircularBuffer =
            new ByteCircularBuffer(MAX_INPUT_SIZE * 2);

        private readonly ByteCircularBuffer _decCircularBuffer =
            new ByteCircularBuffer(RecvBufferCapacity);

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
            long value = 0;
            for (int i = 0; i < 8; i++)
            {
                value = (value << 8) | buf[offset + i];
            }
            return value;
        }

        #region TCP

        public override void Encrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
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
                if (_decCircularBuffer.Size <= ChunkLenBytes + TagSize)
                {
                    return;
                }

                // Peeked, not consumed: the payload may not have arrived yet,
                // and the nonce must not move until we commit to the chunk.
                byte[] sealedLen = _decCircularBuffer.Peek(ChunkLenBytes + TagSize);
                byte[] lenBytes = new byte[ChunkLenBytes];
                _decCipher.Open(_decNonce, sealedLen, sealedLen.Length, lenBytes, 0);
                int chunkLen = ReadUInt16BE(lenBytes, 0);

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

        // SIP022 UDP is a session-based construction with its own separate
        // header, packet ids and replay window, and none of it is reachable
        // through this interface's per-packet shape. Failing loudly beats
        // emitting packets the server will silently drop.
        private const string UdpNotSupported =
            "SIP022 UDP is not implemented; turn off UDP relaying for this server";

        public override void EncryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            throw new NotSupportedException($"{Method}: {UdpNotSupported}");
        }

        public override void DecryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            throw new NotSupportedException($"{Method}: {UdpNotSupported}");
        }

        #endregion

        public override void Dispose()
        {
            _encCipher?.Dispose();
            _encCipher = null;
            _decCipher?.Dispose();
            _decCipher = null;
        }
    }
}
