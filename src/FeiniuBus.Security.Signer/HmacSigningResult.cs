using System.Collections.Generic;

namespace FeiniuBus.Security.Signer
{
    public class HmacSigningResult
    {
        public HmacSigningResult()
        {
            Headers = new Dictionary<string, string>();
        }
        
        public string Signature { get; set; }
        public Dictionary<string, string> Headers { get; set; }
    }
}