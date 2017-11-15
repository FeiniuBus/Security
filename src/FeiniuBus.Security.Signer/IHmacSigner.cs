using System;
using System.Collections.Generic;
using System.Net.Http;

namespace FeiniuBus.Security.Signer
{
    public interface IHmacSigner
    {
        HmacSigningResult Sign(Uri endpoint, byte[] body, IDictionary<string, string> header,
            IDictionary<string, string> parameter, string identifier, string key);
    }
}