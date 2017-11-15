using System.IO;

namespace FeiniuBus.Security.Signer.Util
{
    public interface ICryptoUtil
    {
        string HmacSign(string data, string key, SigningAlgorithm algorithm);
        string HmacSign(byte[] data, string key, SigningAlgorithm algorithm);

        byte[] ComputeSha256Hash(byte[] data);
        byte[] ComputeSha256Hash(Stream stream);

        byte[] ComputeMd5Hash(byte[] data);
        byte[] ComputeMd5Hash(Stream stream);

        byte[] HmacSignBinary(byte[] data, byte[] key, SigningAlgorithm algorithm);
    }
}