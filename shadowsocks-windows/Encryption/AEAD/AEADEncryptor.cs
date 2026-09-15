using NLog;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Shadowsocks.Controller;
using Shadowsocks.Encryption.CircularBuffer;
using Shadowsocks.Encryption.Exception;

namespace Shadowsocks.Encryption.AEAD
{
    public abstract class AEADEncryptor
        : EncryptorBase
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        private const string Info = "ss-subkey";
        private static readonly byte[] InfoBytes = Encoding.ASCII.GetBytes(Info);

        // Receive-side TCP framing still needs to bridge arbitrary socket reads.
        // The send side is processed directly from TCPHandler's input buffer.
        private ByteCircularBuffer _decCircularBuffer;
        private byte[] _decryptSaltBuffer;
        private byte[] _encLengthPlain;
        private byte[] _decLengthCipher;
        private byte[] _decLengthPlain;
        private int _pendingChunkLen = -1;

        public const int CHUNK_LEN_BYTES = 2;
        public const uint CHUNK_LEN_MASK = 0x3FFFu;

        protected Dictionary<string, EncryptorInfo> ciphers;

        protected string _method;
        protected int _cipher;
        protected string _innerLibName;
        protected EncryptorInfo CipherInfo;
        protected byte[] _masterKey;
        protected byte[] _sessionKey;
        protected int keyLen;
        protected int saltLen;
        protected int tagLen;
        protected int nonceLen;

        protected byte[] _encryptSalt;
        protected byte[] _decryptSalt;

        protected byte[] _encNonce;
        protected byte[] _decNonce;
        protected bool _decryptSaltReceived;
        protected bool _encryptSaltSent;
        protected bool _tcpRequestSent;

        public AEADEncryptor(string method, string password)
            : base(method, password)
        {
            InitEncryptorInfo(method);
            InitKey(password);
            _encNonce = new byte[nonceLen];
            _decNonce = new byte[nonceLen];
            _encLengthPlain = new byte[CHUNK_LEN_BYTES];
            _decLengthCipher = new byte[CHUNK_LEN_BYTES + tagLen];
            _decLengthPlain = new byte[CHUNK_LEN_BYTES];
            _decryptSaltBuffer = new byte[saltLen];
        }

        protected abstract Dictionary<string, EncryptorInfo> getCiphers();

        protected void InitEncryptorInfo(string method)
        {
            method = method.ToLowerInvariant();
            _method = method;
            ciphers = getCiphers();
            CipherInfo = ciphers[_method];
            _innerLibName = CipherInfo.InnerLibName;
            _cipher = CipherInfo.Type;
            if (_cipher == 0)
            {
                throw new System.Exception("method not found");
            }
            keyLen = CipherInfo.KeySize;
            saltLen = CipherInfo.SaltSize;
            tagLen = CipherInfo.TagSize;
            nonceLen = CipherInfo.NonceSize;
        }

        protected void InitKey(string password)
        {
            byte[] passbuf = Encoding.UTF8.GetBytes(password);
            _masterKey = new byte[keyLen];
            DeriveKey(passbuf, _masterKey, keyLen);
            _sessionKey = new byte[keyLen];
        }

        public void DeriveKey(byte[] password, byte[] key, int keylen)
        {
            byte[] result = new byte[password.Length + MD5_LEN];
            int i = 0;
            byte[] md5sum = null;
            while (i < keylen)
            {
                if (i == 0)
                {
                    md5sum = LibSsCryptoHash.MD5(password);
                }
                else
                {
                    Array.Copy(md5sum, 0, result, 0, MD5_LEN);
                    Array.Copy(password, 0, result, MD5_LEN, password.Length);
                    md5sum = LibSsCryptoHash.MD5(result);
                }
                Array.Copy(md5sum, 0, key, i, Math.Min(MD5_LEN, keylen - i));
                i += MD5_LEN;
            }
        }

        public void DeriveSessionKey(byte[] salt, byte[] masterKey, byte[] sessionKey)
        {
            int ret = LibSsCryptoHash.hkdf(salt, saltLen, masterKey, keyLen, InfoBytes, InfoBytes.Length,
                sessionKey, keyLen);
            if (ret != 0) throw new System.Exception("failed to generate session key");
        }

        private static void IncrementLittleEndian(byte[] nonce)
        {
            for (int i = 0; i < nonce.Length; i++)
            {
                nonce[i]++;
                if (nonce[i] != 0)
                {
                    break;
                }
            }
        }

        protected void IncrementNonce(bool isEncrypt)
        {
            IncrementLittleEndian(isEncrypt ? _encNonce : _decNonce);
        }

        public virtual void InitCipher(byte[] salt, bool isEncrypt, bool isUdp)
        {
            byte[] target;
            if (isEncrypt)
            {
                if (_encryptSalt == null || _encryptSalt.Length != saltLen)
                {
                    _encryptSalt = new byte[saltLen];
                }
                target = _encryptSalt;
            }
            else
            {
                if (_decryptSalt == null || _decryptSalt.Length != saltLen)
                {
                    _decryptSalt = new byte[saltLen];
                }
                target = _decryptSalt;
            }
            Buffer.BlockCopy(salt, 0, target, 0, saltLen);
            logger.Dump("Salt", salt, saltLen);
        }

        public static void randBytes(byte[] buf, int length) { RNG.GetBytes(buf, length); }

        protected abstract int CipherEncrypt(byte[] plaintext, int plainOffset, int plainLen,
            byte[] ciphertext, int cipherOffset);

        protected abstract int CipherDecrypt(byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plainOffset);

        // Preserve the old public helpers for tests and any out-of-tree callers.
        public virtual void cipherEncrypt(byte[] plaintext, uint plen, byte[] ciphertext, ref uint clen)
        {
            clen = (uint)CipherEncrypt(plaintext, 0, checked((int)plen), ciphertext, 0);
        }

        public virtual void cipherDecrypt(byte[] ciphertext, uint clen, byte[] plaintext, ref uint plen)
        {
            plen = (uint)CipherDecrypt(ciphertext, 0, checked((int)clen), plaintext, 0);
        }

        #region TCP

        public override void Encrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            if (length < 0 || length > buf.Length)
                throw new ArgumentOutOfRangeException(nameof(length));

            outlength = 0;
            int inputOffset = 0;
            logger.Trace("---Start Encryption");

            if (!_encryptSaltSent)
            {
                if (outbuf.Length < saltLen)
                    throw new CryptoErrorException("encryption output buffer is too small for salt");

                _encryptSaltSent = true;
                byte[] saltBytes = new byte[saltLen];
                randBytes(saltBytes, saltLen);
                InitCipher(saltBytes, true, false);
                Buffer.BlockCopy(saltBytes, 0, outbuf, 0, saltLen);
                outlength = saltLen;
            }

            if (!_tcpRequestSent)
            {
                if (AddrBufLength <= 0 || length < AddrBufLength)
                {
                    throw new CryptoErrorException("AEAD target address is incomplete");
                }
                _tcpRequestSent = true;
                int encAddrBufLength = ChunkEncrypt(buf, 0, AddrBufLength, outbuf, outlength);
                Debug.Assert(encAddrBufLength == AddrBufLength + tagLen * 2 + CHUNK_LEN_BYTES);
                outlength += encAddrBufLength;
                inputOffset = AddrBufLength;
            }

            while (inputOffset < length)
            {
                int chunkLength = Math.Min(length - inputOffset, (int)CHUNK_LEN_MASK);
                int framedLength = chunkLength + tagLen * 2 + CHUNK_LEN_BYTES;
                if (outlength > outbuf.Length - framedLength)
                {
                    throw new CryptoErrorException("encryption output buffer is too small for framed data");
                }

                int encryptedLength = ChunkEncrypt(buf, inputOffset, chunkLength, outbuf, outlength);
                Debug.Assert(encryptedLength == framedLength);
                outlength += encryptedLength;
                inputOffset += chunkLength;
            }
        }

        public override void Decrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            if (_decCircularBuffer == null)
            {
                _decCircularBuffer = new ByteCircularBuffer(MAX_INPUT_SIZE * 2);
            }
            _decCircularBuffer.Put(buf, 0, length);
            outlength = 0;

            if (!_decryptSaltReceived)
            {
                if (_decCircularBuffer.Size < saltLen)
                {
                    return;
                }
                _decCircularBuffer.Get(_decryptSaltBuffer, 0, saltLen);
                InitCipher(_decryptSaltBuffer, false, false);
                _decryptSaltReceived = true;
            }

            while (true)
            {
                int bufSize = _decCircularBuffer.Size;
                if (_pendingChunkLen < 0)
                {
                    if (bufSize < CHUNK_LEN_BYTES + tagLen)
                    {
                        return;
                    }

                    _decCircularBuffer.CopyTo(_decLengthCipher);
                    int decLength = CipherDecrypt(_decLengthCipher, 0, _decLengthCipher.Length,
                        _decLengthPlain, 0);
                    Debug.Assert(decLength == CHUNK_LEN_BYTES);
                    _pendingChunkLen = (_decLengthPlain[0] << 8) | _decLengthPlain[1];
                    if (_pendingChunkLen > CHUNK_LEN_MASK)
                    {
                        logger.Error($"Invalid chunk length: {_pendingChunkLen}");
                        throw new CryptoErrorException();
                    }
                }

                int chunkLen = _pendingChunkLen;
                int wholeChunkLength = CHUNK_LEN_BYTES + tagLen + chunkLen + tagLen;
                if (bufSize < wholeChunkLength)
                {
                    return;
                }
                if (outlength > outbuf.Length - chunkLen)
                {
                    return;
                }

                IncrementNonce(false);
                _decCircularBuffer.Skip(CHUNK_LEN_BYTES + tagLen);
                _pendingChunkLen = -1;

                byte[] encryptedChunk = ArrayPool<byte>.Shared.Rent(chunkLen + tagLen);
                try
                {
                    _decCircularBuffer.Get(encryptedChunk, 0, chunkLen + tagLen);
                    int plainLen = CipherDecrypt(encryptedChunk, 0, chunkLen + tagLen,
                        outbuf, outlength);
                    Debug.Assert(plainLen == chunkLen);
                    outlength += plainLen;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(encryptedChunk);
                }
                IncrementNonce(false);
            }
        }

        #endregion

        #region UDP

        public override void EncryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            if (outbuf.Length < saltLen + length + tagLen)
                throw new CryptoErrorException("UDP encryption output buffer is too small");

            randBytes(outbuf, saltLen);
            InitCipher(outbuf, true, true);
            int encryptedLength = CipherEncrypt(buf, 0, length, outbuf, saltLen);
            Debug.Assert(encryptedLength == length + tagLen);
            outlength = saltLen + encryptedLength;
        }

        public override void DecryptUDP(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            if (length < saltLen + tagLen)
                throw new CryptoErrorException("UDP packet is shorter than salt and tag");

            InitCipher(buf, false, true);
            outlength = CipherDecrypt(buf, saltLen, length - saltLen, outbuf, 0);
        }

        #endregion

        private int ChunkEncrypt(byte[] plaintext, int plainOffset, int plainLen,
            byte[] ciphertext, int cipherOffset)
        {
            if (plainLen > CHUNK_LEN_MASK)
            {
                logger.Error("enc chunk too big");
                throw new CryptoErrorException();
            }

            _encLengthPlain[0] = (byte)(plainLen >> 8);
            _encLengthPlain[1] = (byte)plainLen;

            int lengthCipherLen = CipherEncrypt(_encLengthPlain, 0, CHUNK_LEN_BYTES,
                ciphertext, cipherOffset);
            Debug.Assert(lengthCipherLen == CHUNK_LEN_BYTES + tagLen);
            IncrementNonce(true);

            int payloadCipherLen = CipherEncrypt(plaintext, plainOffset, plainLen,
                ciphertext, cipherOffset + lengthCipherLen);
            Debug.Assert(payloadCipherLen == plainLen + tagLen);
            IncrementNonce(true);

            return lengthCipherLen + payloadCipherLen;
        }
    }
}