using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace FeiniuBus.AspNetCore.Authentication.Enterprise
{
    public static class EnterpriseExtensions
    {
        public static AuthenticationBuilder AddEnterprise(this AuthenticationBuilder builder)
            => builder.AddEnterprise(EnterpriseAuthenticationDefaults.AuthenticationScheme, null);

        public static AuthenticationBuilder AddEnterprise(this AuthenticationBuilder builder,
            Action<EnterpriseAuthenticationOptions> configureOptions)
            => builder.AddEnterprise(EnterpriseAuthenticationDefaults.AuthenticationScheme, configureOptions);

        private static AuthenticationBuilder AddEnterprise(this AuthenticationBuilder builder,
            string authenticationScheme, Action<EnterpriseAuthenticationOptions> configureOptions)
        {
            builder.Services.TryAdd(ServiceDescriptor.Singleton<IMemoryCache, MemoryCache>());
            builder.Services.TryAddEnumerable(ServiceDescriptor
                .Singleton<IPostConfigureOptions<EnterpriseAuthenticationOptions>,
                    PostConfigureEnterpriseAuthenticationOptions>());
            return builder.AddScheme<EnterpriseAuthenticationOptions, EnterpriseAuthenticationHandler>(
                authenticationScheme, configureOptions);
        }
    }
}