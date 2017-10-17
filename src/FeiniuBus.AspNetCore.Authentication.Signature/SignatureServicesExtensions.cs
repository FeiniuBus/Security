using System;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace FeiniuBus.AspNetCore.Authentication.Signature
{
    public static class SignatureServicesExtensions
    {
        public static IServiceCollection AddSignature(this IServiceCollection services,
            Action<SignatureOptions> configuration)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }
            
            services.AddOptions();
            services.TryAdd(ServiceDescriptor.Singleton<IMemoryCache, MemoryCache>());
            services.TryAdd(ServiceDescriptor
                .Singleton<IPostConfigureOptions<SignatureOptions>, PostConfigureSignatureOptions>());
            
            services.Configure(configuration);
            return services;
        }
    }
}