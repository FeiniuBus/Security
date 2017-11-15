 using System;
 using System.Collections.Generic;
 using FeiniuBus.Security.Signer.Util;

namespace FeiniuBus.Security.Signer
{
    public abstract class AbstractHmacSigner : IHmacSigner
    {
        public abstract  HmacSigningResult Sign(Uri endpoint, byte[] body, IDictionary<string, string> header,
            IDictionary<string, string> parameter, string identifier,
            string key);

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
    }
}