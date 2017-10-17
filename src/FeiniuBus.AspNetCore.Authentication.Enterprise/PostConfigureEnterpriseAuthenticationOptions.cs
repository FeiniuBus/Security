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
        }
    }
}