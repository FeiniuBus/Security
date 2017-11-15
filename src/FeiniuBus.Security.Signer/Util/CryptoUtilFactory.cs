namespace FeiniuBus.Security.Signer.Util
{
    public static class CryptoUtilFactory
    {
        private static readonly CryptoUtil Util = new CryptoUtil();

        public static ICryptoUtil CryptoInstance => Util;
    }
}