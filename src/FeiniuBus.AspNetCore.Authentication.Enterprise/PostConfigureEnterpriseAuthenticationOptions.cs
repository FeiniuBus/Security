using System;
using System.Net.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace FeiniuBus.AspNetCore.Authentication.Enterprise
{
    public class PostConfigureEnterpriseAuthenticationOptions : IPostConfigureOptions<EnterpriseAuthenticationOptions>
    {
        private readonly IMemoryCache _cache;

        public PostConfigureEnterpriseAuthenticationOptions(IMemoryCache cache)
        {
            _cache = cache;
        }
        
        public void PostConfigure(string name, EnterpriseAuthenticationOptions options)
        {
            if (options.Cache == null)
            {
                options.Cache = _cache;
            }

            if (options.BackChannel == null)
            {
                options.BackChannel = new HttpClient(new HttpClientHandler());
                options.BackChannel.DefaultRequestHeaders.UserAgent.ParseAdd(
                    "FeiniuBus ASP.NET Core enterprise authentication middleware");
                options.BackChannel.MaxResponseContentBufferSize = 1024 * 1024; // 1 MB
                options.BackChannel.Timeout = TimeSpan.FromSeconds(5);  // 5s
            }
        }
    }
}