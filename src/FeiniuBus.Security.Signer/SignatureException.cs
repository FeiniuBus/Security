using System;

namespace FeiniuBus.Security.Signer
{
    public class SignatureException : Exception
    {
        public SignatureException(string message) : base(message)
        {
        }

        public SignatureException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}