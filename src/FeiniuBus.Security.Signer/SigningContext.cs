using System;
using System.Collections.Generic;

namespace FeiniuBus.Security.Signer
{
    public class SigningContext
    {
        public Uri Endpoint { get; set; }
        
        public string Method { get; set; }
        
        public byte[] Body { get; set; }
        
        public Dictionary<string, string> Query { get; set; }
        
        public Dictionary<string, string> Header { get; set; }
        
        public string Identifier { get; set; }
        
        public string Key { get; set; }
    }
}