using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shadowsocks.Encryption.AEAD;

namespace Shadowsocks.Test
{
    /// <summary>
    /// The SIP022 UDP replay filter. This is the one piece of the UDP work that
    /// can be checked without a server on the other end, so it is worth being
    /// thorough about the edges: the window boundary, out-of-order arrivals
    /// inside it, and a jump far enough ahead to invalidate everything held.
    /// </summary>
    [TestClass]
    public class SlidingWindowTest
    {
        [TestMethod]
        public void TestAcceptsAscendingIds()
        {
            var window = new SlidingWindow();
            for (ulong i = 0; i < 1000; i++)
            {
                Assert.IsTrue(window.TryAccept(i), $"id {i} should be new");
            }
        }

        [TestMethod]
        public void TestRejectsDuplicates()
        {
            var window = new SlidingWindow();
            Assert.IsTrue(window.TryAccept(0));
            Assert.IsFalse(window.TryAccept(0));

            Assert.IsTrue(window.TryAccept(7));
            Assert.IsFalse(window.TryAccept(7));
            // The one before it is still unseen, so it is not a replay.
            Assert.IsTrue(window.TryAccept(6));
            Assert.IsFalse(window.TryAccept(6));
        }

        [TestMethod]
        public void TestAcceptsOutOfOrderInsideTheWindow()
        {
            var window = new SlidingWindow();
            Assert.IsTrue(window.TryAccept(100));

            // Everything below the highest but inside the window is still new.
            for (ulong i = 99; i > 0; i--)
            {
                Assert.IsTrue(window.TryAccept(i), $"id {i} should be new");
            }
            for (ulong i = 1; i < 100; i++)
            {
                Assert.IsFalse(window.TryAccept(i), $"id {i} should now be a replay");
            }
        }

        [TestMethod]
        public void TestRejectsIdsThatFellOutOfTheWindow()
        {
            var window = new SlidingWindow();
            Assert.IsTrue(window.TryAccept(0));
            Assert.IsTrue(window.TryAccept(SlidingWindow.WindowSize));

            // Highest is WindowSize, so WindowSize - 1 down to 1 are inside and
            // id 0 has just dropped off the trailing edge.
            Assert.IsTrue(window.TryAccept(1));
            Assert.IsFalse(window.TryAccept(0));
        }

        [TestMethod]
        public void TestWindowEdgeIsExact()
        {
            var window = new SlidingWindow();
            Assert.IsTrue(window.TryAccept(500));

            // 500 - (WindowSize - 1) is the oldest id still representable.
            Assert.IsTrue(window.TryAccept(500 - (SlidingWindow.WindowSize - 1)));
            // One older than that is out of range, seen or not.
            Assert.IsFalse(window.TryAccept(500 - SlidingWindow.WindowSize));
        }

        [TestMethod]
        public void TestFarJumpInvalidatesEverythingHeld()
        {
            var window = new SlidingWindow();
            for (ulong i = 0; i < 10; i++)
            {
                Assert.IsTrue(window.TryAccept(i));
            }

            // Past the whole window: nothing kept can still be in range.
            Assert.IsTrue(window.TryAccept(10 + SlidingWindow.WindowSize * 2));
            Assert.IsFalse(window.TryAccept(5));
            // And the new neighbourhood is untouched.
            Assert.IsTrue(window.TryAccept(10 + SlidingWindow.WindowSize * 2 - 1));
        }

        /// <summary>
        /// A shift of exactly one 64-bit word, where a naive carry would shift
        /// by 64 and get masked back to a no-op.
        /// </summary>
        [TestMethod]
        public void TestShiftByWholeWords()
        {
            var window = new SlidingWindow();
            Assert.IsTrue(window.TryAccept(0));
            Assert.IsTrue(window.TryAccept(64));
            Assert.IsFalse(window.TryAccept(0), "id 0 is still inside the window");
            Assert.IsFalse(window.TryAccept(64));

            Assert.IsTrue(window.TryAccept(128));
            Assert.IsFalse(window.TryAccept(0));
            Assert.IsFalse(window.TryAccept(64));
        }

        [TestMethod]
        public void TestStartingIdNeedNotBeZero()
        {
            var window = new SlidingWindow();
            Assert.IsTrue(window.TryAccept(ulong.MaxValue - 1));
            Assert.IsFalse(window.TryAccept(ulong.MaxValue - 1));
            Assert.IsTrue(window.TryAccept(ulong.MaxValue));
        }
    }
}
