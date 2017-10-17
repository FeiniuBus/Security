namespace FeiniuBus.AspNetCore.Authentication.Signature.Util
{
    internal static class CryptoUtilFactory
    {
        private static readonly CryptoUtil Util = new CryptoUtil();

        public static ICryptoUtil CryptoInstance => Util;
    }
}