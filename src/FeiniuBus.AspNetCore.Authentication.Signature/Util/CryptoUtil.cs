using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace FeiniuBus.AspNetCore.Authentication.Signature.Util
{
    internal class CryptoUtil : ICryptoUtil
    {
        [ThreadStatic] private static HashAlgorithm _hashAlgorithm;

        [ThreadStatic] private static MD5 _md5;
        
        private static HashAlgorithm Sha256HashAlgorithmInstance
            => _hashAlgorithm ?? (_hashAlgorithm = SHA256.Create());

        private static MD5 Md5Instance => _md5 ?? (_md5 = MD5.Create());

        public string HmacSign(string data, string key, SigningAlgorithm algorithm)
        {
            var binary = Encoding.UTF8.GetBytes(data);
            return HmacSign(binary, key, algorithm);
        }

        public string HmacSign(byte[] data, string key, SigningAlgorithm algorithmName)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException(nameof(key), "请指定一个签名的加密密钥");
            if (data == null || data.Length == 0)
                throw new ArgumentNullException(nameof(data), "请指定需要签名的数据");

            var algorithm = CreateKeyedHashAlgorithm(algorithmName);
            if (algorithm == null)
                throw new InvalidOperationException("请指定一个签名的哈希算法: KeyedHashAlgorithm");

            try
            {
                algorithm.Key = Encoding.UTF8.GetBytes(key);
                var bytes = algorithm.ComputeHash(data);
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
            return Md5Instance.ComputeHash(data);
        }

        public byte[] ComputeMd5Hash(Stream stream)
        {
            return Md5Instance.ComputeHash(stream);
        }

        public byte[] HmacSignBinary(byte[] data, byte[] key, SigningAlgorithm algorithmName)
        {
            if (key == null || key.Length == 0)
                throw new ArgumentNullException(nameof(key), "请指定一个签名的加密密钥");
            if (data == null || data.Length == 0)
                throw new ArgumentNullException(nameof(data), "请指定需要签名的数据");

            var algorithm = CreateKeyedHashAlgorithm(algorithmName);
            if (algorithm == null)
                throw new InvalidOperationException("请指定一个签名的哈希算法: KeyedHashAlgorithm");

            try
            {
                algorithm.Key = key;
                var bytes = algorithm.ComputeHash(data);
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
                case SigningAlgorithm.HmacSha1:
                    algorithm = new HMACSHA1();
                    break;
                case SigningAlgorithm.HmacSha256:
                    algorithm = new HMACSHA256();
                    break;
                default:
                    throw new Exception($"没有找到对应的KeyedHashAlgorithm({algorithmName})");
            }

            return algorithm;
        }
    }
}