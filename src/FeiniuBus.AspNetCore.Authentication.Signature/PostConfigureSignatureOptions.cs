using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace FeiniuBus.AspNetCore.Authentication.Signature
{
    public class PostConfigureSignatureOptions : IPostConfigureOptions<SignatureOptions>
    {
        private readonly IMemoryCache _cache;

        public PostConfigureSignatureOptions(IMemoryCache cache)
        {
            _cache = cache;
        }
        
        public void PostConfigure(string name, SignatureOptions options)
        {
            if (options.Cache == null)
            {
                options.Cache = _cache;
            }
        }
    }
}