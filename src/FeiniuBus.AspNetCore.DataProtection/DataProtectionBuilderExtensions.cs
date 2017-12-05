using System;
using Amazon.S3;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;

namespace FeiniuBus.AspNetCore.DataProtection
{
    public static class DataProtectionBuilderExtensions
    {
        public static IDataProtectionBuilder PersistKeysToAwsS3(this IDataProtectionBuilder builder, IAmazonS3 client,
            S3XmlRepositoryConfig config)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }
            if (client == null)
            {
                throw new ArgumentNullException(nameof(client));
            }
            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            builder.Services.Configure<KeyManagementOptions>(options =>
            {
                options.XmlRepository = new S3XmlRepository(client, config);
            });
            return builder;
        }
    }
}