using System;
using System.Linq;
using Amazon.S3;

namespace FeiniuBus.AspNetCore.DataProtection
{
    public interface IS3XmlRepositoryConfig
    {
        string Bucket { get; }
        
        int MaxS3QueryConcurrency { get; }
        
        S3StorageClass StorageClass { get; }
        
        string KeyPrefix { get; }
        
        ServerSideEncryptionMethod ServerSideEncryptionMethod { get; }
        
        ServerSideEncryptionCustomerMethod ServerSideEncryptionCustomerMethod { get; }
        
        string ServerSideEncryptionCustomerProvideKey { get; }
        
        string ServerSideEncryptionCustomerProvideKeyMd5 { get; }
        
        string ServerSideEncryptionKeyManagementServiceKeyId { get; }
        
        bool ClientSideCompression { get; }
    }
    
    public class S3XmlRepositoryConfig : IS3XmlRepositoryConfig
    {
        private string _keyPrefix;

        public S3XmlRepositoryConfig(string bucket)
        {
            Bucket = bucket;
            SetDefault();
        }
        
        public string Bucket { get; }
        public int MaxS3QueryConcurrency { get; set; }
        public S3StorageClass StorageClass { get; set; }
        public ServerSideEncryptionMethod ServerSideEncryptionMethod { get; set; }
        public ServerSideEncryptionCustomerMethod ServerSideEncryptionCustomerMethod { get; set; }
        public string ServerSideEncryptionCustomerProvideKey { get; set; }
        public string ServerSideEncryptionCustomerProvideKeyMd5 { get; set; }
        public string ServerSideEncryptionKeyManagementServiceKeyId { get; set; }
        public bool ClientSideCompression { get; set; }

        public string KeyPrefix
        {
            get => _keyPrefix;
            set
            {
                if (!IsSateS3Key(value))
                {
                    throw new ArgumentException($"Specified key prefix {value} is not considered a safe S3 name",
                        nameof(value));
                }
                _keyPrefix = value;
            }
        }

        private static bool IsSateS3Key(string key)
        {
            return !string.IsNullOrEmpty(key) &&
                   key.All(c =>
                       c == '!' ||
                       c == '-' ||
                       c == '_' ||
                       c == '.' ||
                       c == '*' ||
                       c == '\'' ||
                       c == '(' ||
                       c == ')' ||
                       c == '/' ||
                       '0' <= c && c <= '9' ||
                       'A' <= c && c <= 'Z' ||
                       'a' <= c && c <= 'z') && !key.StartsWith("/");
        }

        private void SetDefault()
        {
            KeyPrefix = "DataProtection-Keys/";
            MaxS3QueryConcurrency = 10;
            StorageClass = S3StorageClass.Standard;
            ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256;
            ServerSideEncryptionCustomerMethod = ServerSideEncryptionCustomerMethod.None;
            ServerSideEncryptionCustomerProvideKey = null;
            ServerSideEncryptionCustomerProvideKeyMd5 = null;
            ServerSideEncryptionKeyManagementServiceKeyId = null;
            ClientSideCompression = true;
        }
    }
}