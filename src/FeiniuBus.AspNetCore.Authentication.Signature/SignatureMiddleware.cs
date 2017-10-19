using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using FeiniuBus.AspNetCore.Authentication.Signature.Util;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace FeiniuBus.AspNetCore.Authentication.Signature
{
    public class SignatureMiddleware
    {
        private const string SecretAccessKeyCachePrefix = "SecretAccessKey";
        private readonly ILogger _logger;
        private readonly RequestDelegate _next;

        public SignatureMiddleware(RequestDelegate next, ILogger<SignatureMiddleware> logger,
            IOptions<SignatureOptions> options)
        {
            _next = next;
            _logger = logger;

            Options = options.Value;
            Backchannel = new HttpClient(Options.BackchannelHttpHandler ?? new HttpClientHandler());
            Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd(
                "FeiniuBus ASP.NET Core Signature verification middleware");
            Backchannel.MaxResponseContentBufferSize = 1024 * 1024; // 1 MB
            Backchannel.Timeout = TimeSpan.FromSeconds(5);  // 5s
        }
        
        protected HttpClient Backchannel { get; }
        
        protected SignatureOptions Options { get; }

        public async Task Invoke(HttpContext context)
        {
            if (!context.Request.Body.CanSeek)
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("未引入RequestBuffering中间件，无法验证签名");
                return;
            }

            var result = await VerifySignatureAsync(context.Request);
            if (!result)
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("验证签名失败");
                return;
            }
            await _next(context);
        }

        private async Task<bool> VerifySignatureAsync(HttpRequest req)
        {
            string authorization = req.Headers[HeaderKeys.AuthorizationHeader];
            if (string.IsNullOrEmpty(authorization))
                return false;

            if (!authorization.StartsWith("FNSIGN ", StringComparison.OrdinalIgnoreCase))
                return false;

            var token = authorization.Substring("FNSIGN ".Length).Trim();
            var segments = token.Split(new[] {','}, StringSplitOptions.None);
            if (segments.Length != 2)
                return false;

            var accessKeyId = segments[0].Split(new[] {'='}, StringSplitOptions.None)[1];
            if (string.IsNullOrEmpty(accessKeyId))
                return false;

            var secret = await GetSecretAccessKeyAsync(accessKeyId);
            if (string.IsNullOrEmpty(secret))
                return false;

            var verifyData = segments[1].Split(new[] {'='}, StringSplitOptions.None)[1];
            if (string.IsNullOrEmpty(verifyData))
                return false;

            var signature = Signer.Sign(req, accessKeyId, secret);
            var verifyBytes = SignatureUtils.HexStringToBytes(verifyData);

            if (!signature.SequenceEqual(verifyBytes))
            {
                req.Headers.TryGetValue(HeaderKeys.XFeiniuBusDateHeader, out StringValues signAt);

                _logger.LogWarning(897, "验证签名失败，原始签名: {0}, 实际签名: {1}, 签名时间戳: {2}", verifyData,
                    SignatureUtils.ToHex(signature, true), signAt);
                return false;
            }

            req.Headers.Add(HeaderKeys.XFeiniuBusAccessKeyHeader, accessKeyId);
            return true;
        }

        private async Task<string> GetSecretAccessKeyAsync(string accessKeyId)
        {
            string secret;
            if (Options.EnableCaching)
            {
                secret = GetSecretAccessKeyFromCache(accessKeyId);
                if (!string.IsNullOrEmpty(secret))
                {
                    return secret;
                }
            }

            secret = await GetSecretAccessKeyFromServerAsync(accessKeyId).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(secret))
            {
                SetSecretAccessKeyToCache(accessKeyId, secret);
            }

            return secret;
        }

        private string GetSecretAccessKeyFromCache(string accessKeyId)
        {
            try
            {
                var key = GetLocalizedKey(accessKeyId);
                var data = Options.Cache.Get<byte[]>(key);

                var secret = Encoding.UTF8.GetString(data, 0, data.Length);
                return secret;
            }
            catch (Exception e)
            {
                _logger.LogWarning(898, e, "从缓存中获取数据失败");
                return null;
            }
        }

        private void SetSecretAccessKeyToCache(string accessKeyId, string secret)
        {
            try
            {
                var memoryCacheEntryOptions =
                    new MemoryCacheEntryOptions {AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(30)};

                Options.Cache.Set(GetLocalizedKey(accessKeyId), Encoding.UTF8.GetBytes(secret),
                    memoryCacheEntryOptions);
            }
            catch (Exception e)
            {
                _logger.LogError(898, e, "向缓存中写入密钥数据失败");
            }
        }

        private async Task<string> GetSecretAccessKeyFromServerAsync(string accessKeyId)
        {
            var builder = new UriBuilder(Options.Endpoint) {Query = QueryString.Create("accessKey", accessKeyId).Value};

            try
            {
                var req = new HttpRequestMessage(HttpMethod.Get, builder.Uri);
                var resp = await Backchannel.SendAsync(req).ConfigureAwait(false);
                resp.EnsureSuccessStatusCode();

                var secret = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                return secret;
            }
            catch (Exception e)
            {
                _logger.LogError(898, e, "从服务器获取用户访问密钥失败, 请求地址：" + builder.Uri);
                return null;
            }
        }

        private static string GetLocalizedKey(string accessKeyId)
        {
            return $"{SecretAccessKeyCachePrefix}_{accessKeyId}";
        }
    }
}