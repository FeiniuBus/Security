namespace FeiniuBus.Security.Signer.Util
{
    public interface ICryptoUtil
    {
        string HmacSign(string data, string key);
    }
}