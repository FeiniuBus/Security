 using System;
 using System.Collections.Generic;
 using System.Text;
 using FeiniuBus.Security.Signer.Util;

namespace FeiniuBus.Security.Signer
{
    public abstract class AbstractHmac
    {
        protected static string ComputeHash(string data, string key, SigningAlgorithm algorithm)
        {
            try
            {
                return CryptoUtilFactory.CryptoInstance.HmacSign(data, key, algorithm);

            }
            catch (Exception e)
            {
                throw new SignatureException("Failed to generate signature: " + e.Message, e);
            }
        }

        protected static string ComputeHash(byte[] data, string key, SigningAlgorithm algorithm)
        {
            try
            {
                return CryptoUtilFactory.CryptoInstance.HmacSign(data, key, algorithm);
            }
            catch (Exception e)
            {
                throw new SignatureException("Failed to generate signature: " + e.Message, e);
            }
        }

        protected static byte[] ComputeKeyedHash(SigningAlgorithm algorithm, byte[] key, string data)
        {
            return ComputeKeyedHash(algorithm, key, Encoding.UTF8.GetBytes(data));
        }

        protected static byte[] ComputeKeyedHash(SigningAlgorithm algorithm, byte[] key, byte[] data)
        {
            return CryptoUtilFactory.CryptoInstance.HmacSignBinary(data, key, algorithm);
        }

        protected static byte[] ComputeHash(string data)
        {
            return ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        protected static byte[] ComputeHash(byte[] data)
        {
            return CryptoUtilFactory.CryptoInstance.ComputeSha256Hash(data);
        }
    }
}