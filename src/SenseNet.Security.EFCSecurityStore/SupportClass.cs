namespace SenseNet.Security.EFCSecurityStore
{
    internal static class SupportClass
    {
        internal static ulong ToUInt64(this long value)
        {
            if (value >= 0)
                return (ulong)value;
            return (ulong)(value & 0x7FFFFFFFFFFFFFFF) | 0x8000000000000000;
        }
        internal static long ToInt64(this ulong value)
        {
            return (long)value;
        }
    }
}
