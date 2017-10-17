using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;

namespace FeiniuBus.AspNetCore.Authentication.Enterprise
{
    public class EnterpriseAuthenticationOptions : AuthenticationSchemeOptions
    {
        public EnterpriseAuthenticationOptions()
        {
            EnableCaching = true;
        }
        
        public string Authority { get; set; }
        
        public bool EnableCaching { get; set; }
        
        public IMemoryCache Cache { get; set; }
        
        public int? AbsoluteExpirationRelativeToNow { get; set; }
    }
}