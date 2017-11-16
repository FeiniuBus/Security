using FeiniuBus.Security.Signer.Util;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace FeiniuBus.Security.Signer
{
    public class FeiniuBus1HmacValidator : AbstractHmac, IHmacValidator
    {
        private readonly ILogger _logger;

        public FeiniuBus1HmacValidator(ILoggerFactory factory)
        {
            _logger = factory.CreateLogger<FeiniuBus1HmacValidator>();
        }
        
        public bool Verify(VerifingContext ctx)
        {
            throw new System.NotImplementedException();
        }

        private bool VerifyRequest(VerifingContext ctx)
        {
            StringValues signAt;
            if (!ctx.Header.TryGetValue(HeaderKeys.XFeiniuBusDateHeader, out signAt))
            {
                _logger.LogWarning(897, "请求未包含签名时间戳");
                return false;
            }
            return false;
        }
    }
}