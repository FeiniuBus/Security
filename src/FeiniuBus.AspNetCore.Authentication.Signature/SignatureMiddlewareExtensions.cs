using System;
using Microsoft.AspNetCore.Builder;

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

            return builder.UseMiddleware<SignatureMiddleware>();
        }
    }
}