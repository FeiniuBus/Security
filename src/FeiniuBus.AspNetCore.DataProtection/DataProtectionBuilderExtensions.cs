using System;
using Amazon.S3;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

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

            Use(builder.Services,
                ServiceDescriptor.Singleton<IXmlRepository>(services =>
                    new S3XmlRepository(client, config, services.GetRequiredService<ILogger<S3XmlRepository>>())));

            return builder;
        }

        public static IDataProtectionBuilder PersistKeysToAwsS3(this IDataProtectionBuilder builder,
            S3XmlRepositoryConfig config)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }
            if (config == null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            Use(builder.Services,
                ServiceDescriptor.Singleton<IXmlRepository>(services =>
                    new S3XmlRepository(services.GetRequiredService<IAmazonS3>(), config,
                        services.GetRequiredService<ILogger<S3XmlRepository>>())));

            return builder;
        }

        private static void Use(IServiceCollection services, ServiceDescriptor descriptor)
        {
            RemoveAllServicesOfType(services, descriptor.ServiceType);
            services.Add(descriptor);
        }

        private static void RemoveAllServicesOfType(IServiceCollection services, Type serviceType)
        {
            for (var i = services.Count - 1; i >= 0; i--)
            {
                if (services[i].ServiceType == serviceType)
                {
                    services.RemoveAt(i);
                }
            }
        }
    }
}