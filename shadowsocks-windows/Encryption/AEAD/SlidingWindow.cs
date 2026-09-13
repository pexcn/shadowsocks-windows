using System;

namespace Shadowsocks.Encryption.AEAD
{
    /// <summary>
    /// Anti-replay filter over the monotonically issued packet ids of one
    /// SIP022 UDP relay session. A packet id that repeats, or that has fallen
    /// further behind the highest one seen than the window is wide, is refused.
    ///
    /// Bit i of the bitmap stands for the packet id <c>Highest - i</c>, so the
    /// window slides by shifting the bitmap toward higher indices.
    /// </summary>
    public sealed class SlidingWindow
    {
        public const int WindowSize = 256;

        private const int WordBits = 64;

        private readonly ulong[] _seen = new ulong[WindowSize / WordBits];
        private ulong _highest;
        private bool _anySeen;

        /// <summary>
        /// Records <paramref name="packetId"/> and returns true if it is new and
        /// still inside the window; returns false, changing nothing, for a
        /// duplicate or for one that is too old.
        /// </summary>
        public bool TryAccept(ulong packetId)
        {
            if (!_anySeen)
            {
                _anySeen = true;
                _highest = packetId;
                Set(0);
                return true;
            }

            if (packetId > _highest)
            {
                ulong ahead = packetId - _highest;
                if (ahead >= WindowSize)
                {
                    // Everything the window held is now out of range.
                    Array.Clear(_seen, 0, _seen.Length);
                }
                else
                {
                    ShiftUp((int)ahead);
                }

                _highest = packetId;
                Set(0);
                return true;
            }

            ulong behind = _highest - packetId;
            if (behind >= WindowSize)
            {
                return false;
            }

            int bit = (int)behind;
            if (IsSet(bit))
            {
                return false;
            }

            Set(bit);
            return true;
        }

        private void ShiftUp(int distance)
        {
            int wordShift = distance / WordBits;
            int bitShift = distance % WordBits;

            for (int i = _seen.Length - 1; i >= 0; i--)
            {
                int source = i - wordShift;
                ulong value = 0;
                if (source >= 0)
                {
                    value = _seen[source] << bitShift;
                    // A shift of 64 is not a shift at all in C#: the count is
                    // masked to 63, so the carry has to be skipped explicitly.
                    if (bitShift != 0 && source - 1 >= 0)
                    {
                        value |= _seen[source - 1] >> (WordBits - bitShift);
                    }
                }
                _seen[i] = value;
            }
        }

        private void Set(int bit)
        {
            _seen[bit / WordBits] |= 1UL << (bit % WordBits);
        }

        private bool IsSet(int bit)
        {
            return (_seen[bit / WordBits] & (1UL << (bit % WordBits))) != 0;
        }
    }
}
