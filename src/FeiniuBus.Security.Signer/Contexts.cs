using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Http;

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

    public class VerifingContext
    {
        public PathString Path { get; set; }
        
        public string Method { get; set; }
        
        public byte[] Body { get; set; }
        
        public IQueryCollection Query { get; set; }
        
        public IHeaderDictionary Header { get; set; }
    }
}