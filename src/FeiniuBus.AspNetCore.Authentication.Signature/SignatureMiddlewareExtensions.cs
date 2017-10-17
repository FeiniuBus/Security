using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace FeiniuBus.AspNetCore.Authentication.Signature
{
    public static class SignatureMiddlewareExtensions
    {
        public static IApplicationBuilder UseSignature(this IApplicationBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            var options = builder.ApplicationServices.GetRequiredService<IOptions<SignatureOptions>>().Value;
            if (options.Cache == null)
            {
                options.Cache = builder.ApplicationServices.GetService<IMemoryCache>();
                if (options.Cache == null && options.EnableCaching)
                {
                    throw new InvalidOperationException("你必须将一个 IMemoryCache 接口的实现注册到 SignatureOptions 中，或者注入依赖容器中");
                }
            }

            return builder.UseMiddleware<SignatureMiddleware>();
        }
    }
}