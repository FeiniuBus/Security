using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.AspNetCore.DataProtection.Repositories;

namespace FeiniuBus.AspNetCore.DataProtection
{
    public class S3XmlRepository : IXmlRepository
    {
        private readonly IAmazonS3 _client;

        private const string FriendlyNameMetadata = "xml-friendly-name";

        public S3XmlRepository(IAmazonS3 client, IS3XmlRepositoryConfig config)
        {
            _client = client;

            Config = config ?? throw new ArgumentNullException(nameof(config));
        }
        
        public IS3XmlRepositoryConfig Config { get; }
        
        public IReadOnlyCollection<XElement> GetAllElements()
        {
            // Due to time constraints, Microsoft didn't make the interfaces async
            // https://github.com/aspnet/DataProtection/issues/124
            // so loft the heavy lifting into a thread which enables safe async behaviour with some additional cost
            // Overhead should be acceptable since key management isn't a frequent thing
            return GetAllElementsAsync(CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        public void StoreElement(XElement element, string friendlyName)
        {
            StoreElementAsync(element, friendlyName, CancellationToken.None).ConfigureAwait(false).GetAwaiter()
                .GetResult();
        }

        public async Task<IReadOnlyCollection<XElement>> GetAllElementsAsync(CancellationToken cancellation)
        {
            var items = new List<S3Object>();
            ListObjectsV2Response response = null;

            do
            {
                response = await _client.ListObjectsV2Async(new ListObjectsV2Request
                {
                    BucketName = Config.Bucket,
                    Prefix = Config.KeyPrefix,
                    ContinuationToken = response?.NextContinuationToken
                }, cancellation);

                items.AddRange(response.S3Objects);
            } while (response.IsTruncated);

            using (var throttler = new SemaphoreSlim(Config.MaxS3QueryConcurrency))
            {
                var queries = new List<Task<XElement>>();
                foreach (var item in items)
                {
                    queries.Add(GetElementFromKeyAsync(item, throttler, cancellation));
                }

                await Task.WhenAll(queries).ConfigureAwait(false);

                return new ReadOnlyCollection<XElement>(queries.Select(x => x.Result).Where(x => x != null).ToList());
            }
        }

        public async Task StoreElementAsync(XElement element, string friendlyName, CancellationToken cancellation)
        {
            var key = Config.KeyPrefix + Guid.NewGuid() + ".xml";
            
            var pr = new PutObjectRequest
            {
                BucketName = Config.Bucket,
                Key = key,
                ServerSideEncryptionMethod = Config.ServerSideEncryptionMethod,
                ServerSideEncryptionCustomerMethod = ServerSideEncryptionCustomerMethod.None,
                AutoResetStreamPosition = false,
                AutoCloseStream = true,
                ContentType = "text/xml",
                StorageClass = Config.StorageClass
            };
            pr.Metadata.Add(FriendlyNameMetadata, friendlyName);
            pr.Headers.ContentDisposition = "attachment; filename=" + friendlyName + ".xml";

            if (Config.ServerSideEncryptionMethod == ServerSideEncryptionMethod.AWSKMS)
            {
                pr.ServerSideEncryptionKeyManagementServiceKeyId = Config.ServerSideEncryptionKeyManagementServiceKeyId;
            }
            else if (Config.ServerSideEncryptionCustomerMethod != ServerSideEncryptionCustomerMethod.None)
            {
                pr.ServerSideEncryptionMethod = ServerSideEncryptionMethod.None;
                pr.ServerSideEncryptionCustomerMethod = Config.ServerSideEncryptionCustomerMethod;
                pr.ServerSideEncryptionCustomerProvidedKey = Config.ServerSideEncryptionCustomerProvideKey;
                pr.ServerSideEncryptionCustomerProvidedKeyMD5 = Config.ServerSideEncryptionCustomerProvideKeyMd5;
            }

            using (var output = new MemoryStream())
            {
                if (Config.ClientSideCompression)
                {
                    pr.Headers.ContentEncoding = "gzip";
                    using (var input = new MemoryStream())
                    {
                        using (var gzip = new GZipStream(input, CompressionMode.Compress, true))
                        {
                            element.Save(gzip);
                        }
                        var inputArray = input.ToArray();
                        await output.WriteAsync(inputArray, 0, inputArray.Length, cancellation);
                    }
                }
                else
                {
                    element.Save(output);
                }

                output.Seek(0, SeekOrigin.Begin);
                using (var hasher = MD5.Create())
                {
                    pr.MD5Digest = Convert.ToBase64String(hasher.ComputeHash(output));
                }

                output.Seek(0, SeekOrigin.Begin);
                pr.InputStream = output;

                await _client.PutObjectAsync(pr, cancellation).ConfigureAwait(false);
            }
        }

        private async Task<XElement> GetElementFromKeyAsync(S3Object item, SemaphoreSlim throttler,
            CancellationToken cancellation)
        {
            await throttler.WaitAsync(cancellation);

            try
            {
                var gr = new GetObjectRequest
                {
                    BucketName = Config.Bucket,
                    Key = item.Key,
                    ServerSideEncryptionCustomerMethod = ServerSideEncryptionCustomerMethod.None
                };

                if (Config.ServerSideEncryptionCustomerMethod != ServerSideEncryptionCustomerMethod.None)
                {
                    gr.ServerSideEncryptionCustomerMethod = Config.ServerSideEncryptionCustomerMethod;
                    gr.ServerSideEncryptionCustomerProvidedKey = Config.ServerSideEncryptionCustomerProvideKey;
                    gr.ServerSideEncryptionCustomerProvidedKeyMD5 = Config.ServerSideEncryptionCustomerProvideKeyMd5;
                }

                using (var response = await _client.GetObjectAsync(gr, cancellation).ConfigureAwait(false))
                {
                    if (item.Key.EndsWith("/") && response.ContentLength == 0)
                    {
                        return null;
                    }

                    if (response.Headers.ContentEncoding == "gzip")
                    {
                        using (var responseStream = new GZipStream(response.ResponseStream, CompressionMode.Decompress))
                        {
                            return XElement.Load(responseStream);
                        }
                    }
                    else
                    {
                        return XElement.Load(response.ResponseStream);
                    }
                }
            }
            finally
            {
                throttler.Release();
            }
        }
    }
}