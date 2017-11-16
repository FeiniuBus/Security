using System;
using System.Collections.Generic;
using System.Net.Http;

namespace FeiniuBus.Security.Signer
{
    public interface IHmacSigner
    {
        HmacSigningResult Sign(SigningContext ctx);
    }

    public interface IHmacValidator
    {
        bool Verify(VerifingContext ctx);
    }
}