using System;
using Microsoft.Extensions.DependencyInjection;

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
            services.Configure(configuration);
            return services;
        }
    }
}