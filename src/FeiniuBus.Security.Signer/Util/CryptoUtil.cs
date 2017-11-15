using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FeiniuBus.Security.Signer.Util
{
    public class CryptoUtil : ICryptoUtil
    {
        public string HmacSign(string data, string key, SigningAlgorithm algorithmName)
        {
            var binaryData = Encoding.UTF8.GetBytes(data);
            return HmacSign(binaryData, key, algorithmName);
        }

        public string HmacSign(byte[] data, string key, SigningAlgorithm algorithmName)
        {
            if (string.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException(nameof(key), "Please specify a Secret Sign Key.");
            }
            if (data == null || data.Length == 0)
            {
                throw new ArgumentNullException(nameof(data), "Please specify data to sign.");
            }

            KeyedHashAlgorithm algorithm = CreateKeyedHashAlgorithm(algorithmName);
            if (algorithm == null)
            {
                throw new InvalidOperationException("Please specify a KeyedHashAlgorithm to use.");
            }

            try
            {
                algorithm.Key = Encoding.UTF8.GetBytes(key);
                byte[] bytes = algorithm.ComputeHash(data);
                return Convert.ToBase64String(bytes);
            }
            finally
            {
                algorithm.Dispose();
            }
        }

        public byte[] ComputeSha256Hash(byte[] data)
        {
            return Sha256HashAlgorithmInstance.ComputeHash(data);
        }

        public byte[] ComputeSha256Hash(Stream stream)
        {
            return Sha256HashAlgorithmInstance.ComputeHash(stream);
        }

        public byte[] ComputeMd5Hash(byte[] data)
        {
            return Md5HashAlgorithmInstance.ComputeHash(data);
        }

        public byte[] ComputeMd5Hash(Stream stream)
        {
            return Md5HashAlgorithmInstance.ComputeHash(stream);
        }

        public byte[] HmacSignBinary(byte[] data, byte[] key, SigningAlgorithm algorithmName)
        {
            if (key == null || key.Length == 0)
            {
                throw new ArgumentNullException(nameof(key), "Please specify a Secret Signing Key.");
            }
            if (data == null || data.Length == 0)
            {
                throw new ArgumentNullException(nameof(data), "Please specify data to sign.");
            }

            KeyedHashAlgorithm algorithm = CreateKeyedHashAlgorithm(algorithmName);
            if (algorithm == null)
            {
                throw new InvalidOperationException("Please specify a KeyedHashAlgorithm to use.");
            }

            try
            {
                algorithm.Key = key;
                byte[] bytes = algorithm.ComputeHash(data);
                return bytes;
            }
            finally
            {
                algorithm.Dispose();
            }
        }

        private KeyedHashAlgorithm CreateKeyedHashAlgorithm(SigningAlgorithm algorithmName)
        {
            KeyedHashAlgorithm algorithm;
            switch (algorithmName)
            {
                case SigningAlgorithm.HmacSHA256:
                    algorithm = new HMACSHA256();
                    break;
                case SigningAlgorithm.HmacSHA1:
                    algorithm = new HMACSHA1();
                    break;
                case SigningAlgorithm.Md5:
                    algorithm = new HMACMD5();
                    break;
                default:
                    throw new Exception(string.Format("KeyedHashAlgorithm {0} was not found.",
                        algorithmName.ToString()));
            }

            return algorithm;
        }

        [ThreadStatic] private static HashAlgorithm _md5Algorithm;

        private static HashAlgorithm Md5HashAlgorithmInstance => _md5Algorithm ?? (_md5Algorithm = MD5.Create());

        [ThreadStatic] private static HashAlgorithm _hashAlgorithm;

        private static HashAlgorithm Sha256HashAlgorithmInstance =>
            _hashAlgorithm ?? (_hashAlgorithm = SHA256.Create());
    }
}