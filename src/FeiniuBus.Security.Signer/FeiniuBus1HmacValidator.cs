using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using FeiniuBus.Security.Signer.Util;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace FeiniuBus.Security.Signer
{
    public class FeiniuBus1HmacValidator : AbstractHmac, IHmacValidator
    {
        private readonly ILogger _logger;
        private readonly Func<string, string> _getKeyFunc;

        public FeiniuBus1HmacValidator(ILoggerFactory factory, Func<string, string> getKeyFunc)
        {
            _logger = factory.CreateLogger<FeiniuBus1HmacValidator>();
            _getKeyFunc = getKeyFunc;
        }
        
        public bool Verify(VerifingContext ctx)
        {
            if (!ctx.Header.TryGetValue(HeaderKeys.XFeiniuBusDateHeader, out var signAt))
            {
                _logger.LogWarning(897, "请求未包含签名时间戳");
                return false;
            }

            if (!ctx.Header.TryGetValue(HeaderKeys.AuthorizationHeader, out var authString))
            {
                _logger.LogWarning(897, "请求未包含签名认证头");
                return false;
            }

            return VerifyRequest(ctx, signAt, authString);
        }

        private bool VerifyRequest(VerifingContext ctx, string signAt, string authString)
        {
            var parts = authString.Split(new[] {' '}, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2)
            {
                _logger.LogWarning(897, "请求签名认证头格式错误：{0}", authString);
                return false;
            }

            if (parts[0] != Constants.FeiniuBus1AlgorithmTag)
            {
                _logger.LogWarning(897, "签名认证架构错误：{0}", parts[0]);
                return false;
            }

            var scheme = parts[0].Split(new[] {'-'}, StringSplitOptions.RemoveEmptyEntries)[0];

            var auths = parts[1].Split(new[] {','}, StringSplitOptions.RemoveEmptyEntries);
            if (auths.Length != 3)
            {
                _logger.LogWarning(897, "请求签名体的格式不正确: {0}", parts[1]);
                return false;
            }

            if (!TryParseCredential(auths[0], out var id, out var shortedTime, out var credSuffix))
            {
                _logger.LogWarning(897, "Credential节错误: {0}", auths[0]);
                return false;
            }
            if (!TryParseSignedHeaders(auths[1], out var signedHeaders))
            {
                _logger.LogWarning(897, "SignedHeaders节错误：{0}", auths[1]);
                return false;
            }
            if (!TryParseSignature(auths[2], out var clientSignatures))
            {
                _logger.LogWarning(897, "Signature节错误：{0}",auths[2]);
                return false;
            }

            var credentialString = BuildCredentialString(shortedTime, credSuffix);
            var bodyHash = SetRequestBodyHash(ctx.Body);

            var parametersToCanonicalize =
                GetParametersToCanonicalize(ctx.Query.ToDictionary(x => x.Key, y => y.Value.ToString()));
            var canonicalQueryParams = CanonicalizeQueryParameters(parametersToCanonicalize);

            var canonicalRequest = CanonicalizeRequest(ctx.Path, ctx.Method, ctx.Header, signedHeaders,
                canonicalQueryParams, bodyHash);

            var key = _getKeyFunc(id);
            var signature = ComputeSignature(key, parts[0], signAt, shortedTime, credentialString, canonicalRequest,
                scheme, credSuffix);

            return clientSignatures == signature;
        }

        private static string ComputeSignature(string key, string authPrefix, string signAt, string shortedTime,
            string credentialString, string canonicalRequest, string scheme, string terminal)
        {
            var stringToSignBuilder = new StringBuilder();
            stringToSignBuilder.AppendFormat(CultureInfo.InvariantCulture, "{0}\n{1}\n{2}\n",
                authPrefix,
                signAt,
                credentialString);

            var canonicalRequestHashBytes = ComputeHash(canonicalRequest);
            stringToSignBuilder.Append(Hex.EncodeToString(canonicalRequestHashBytes, true));

            var keyBytes = ComposeSigningKey(key, shortedTime, scheme, terminal);
            var signature = ComputeKeyedHash(SigningAlgorithm.HmacSHA256, keyBytes, stringToSignBuilder.ToString());
            return Hex.EncodeToString(signature, true);
        }

        private static byte[] ComposeSigningKey(string key, string shortedTime, string scheme, string terminal)
        {
            char[] ksecret = null;

            try
            {
                ksecret = (scheme + key).ToCharArray();
                var hashDate = ComputeKeyedHash(SigningAlgorithm.HmacSHA256, Encoding.UTF8.GetBytes(ksecret),
                    Encoding.UTF8.GetBytes(shortedTime));
                return ComputeKeyedHash(SigningAlgorithm.HmacSHA256, hashDate, Encoding.UTF8.GetBytes(terminal));
            }
            finally
            {
                if (ksecret != null)
                {
                    Array.Clear(ksecret, 0, ksecret.Length);
                }
            }
        }

        private static string CanonicalizeRequest(string path, string method, IHeaderDictionary headers,
            string signedHeaders, string queryString, string bodyHash)
        {
            var canonicalRequest = new StringBuilder();
            canonicalRequest.AppendFormat("{0}\n", method);
            canonicalRequest.AppendFormat("{0}\n", path);
            canonicalRequest.AppendFormat("{0}\n", queryString);
            canonicalRequest.AppendFormat("{0}\n", CanonicalizeHeaders(headers, signedHeaders));
            canonicalRequest.AppendFormat("{0}\n", signedHeaders);

            if (bodyHash != null)
            {
                canonicalRequest.Append(bodyHash);
            }

            return canonicalRequest.ToString();
        }

        private static string CanonicalizeHeaders(IHeaderDictionary header, string signedHeaders)
        {
            var headerNames = signedHeaders.Split(new[] {';'}, StringSplitOptions.RemoveEmptyEntries);
            var builder = new StringBuilder();

            foreach (var headerName in headerNames)
            {
                header.TryGetValue(headerName, out var value);
                builder.Append(headerName);
                builder.Append(":");
                builder.Append(CompressSpaces(value));
                builder.Append("\n");
            }

            return builder.ToString();
        }

        private static string CanonicalizeQueryParameters(IEnumerable<KeyValuePair<string, string>> parameters,
            bool uriEncodeParameters = true)
        {
            if (parameters == null)
            {
                return string.Empty;
            }

            var sortedParameters = parameters.OrderBy(x => x.Key, StringComparer.Ordinal).ToList();
            var canonicalQueryString = new StringBuilder();
            foreach (var param in sortedParameters)
            {
                var key = param.Key;
                var value = param.Value;
                
                if (canonicalQueryString.Length > 0)
                {
                    canonicalQueryString.Append("&");
                }
                if (uriEncodeParameters)
                {
                    if (string.IsNullOrEmpty(value))
                    {
                        canonicalQueryString.AppendFormat("{0}=", WebUtility.UrlEncode(key));
                    }
                    else
                    {
                        canonicalQueryString.AppendFormat("{0}={1}", WebUtility.UrlEncode(key), WebUtility.UrlEncode(value));
                    }
                }
                else
                {
                    if (string.IsNullOrEmpty(value))
                    {
                        canonicalQueryString.AppendFormat("{0}=", key);
                    }
                    else
                    {
                        canonicalQueryString.AppendFormat("{0}={1}", key, value);
                    }
                }
            }

            return canonicalQueryString.ToString();
        }

        private static List<KeyValuePair<string, string>> GetParametersToCanonicalize(IDictionary<string, string> query)
        {
            var parametersToCanonicalize = new List<KeyValuePair<string, string>>();
            if (query != null && query.Count > 0)
            {
                var requestParameters = new SortedDictionary<string, string>(query);
                foreach (var queryParameter in requestParameters.Where(x => x.Value != null))
                {
                    parametersToCanonicalize.Add(
                        new KeyValuePair<string, string>(queryParameter.Key, queryParameter.Value));
                }
            }

            return parametersToCanonicalize;
        }

        private static string SetRequestBodyHash(byte[] body)
        {
            if (body == null || body.Length == 0)
            {
                return Constants.EmptyBodySha256;
            }

            var hashed = CryptoUtilFactory.CryptoInstance.ComputeSha256Hash(body);
            return Hex.EncodeToString(hashed, true);
        }

        private static string BuildCredentialString(string shortedTime, string credSuffix)
        {
            var credentialStringBuilder = new StringBuilder();
            credentialStringBuilder.AppendFormat("{0}/{1}", shortedTime, credSuffix);
            return credentialStringBuilder.ToString();
        }

        private static bool TryParseCredential(string cred, out string identifier, out string shortedTime,
            out string credSuffix)
        {
            var parts = cred.Split(new[] {'='}, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2)
            {
                identifier = shortedTime = credSuffix = string.Empty;
                return false;
            }

            var values = parts[1].Split(new[] {'/'}, StringSplitOptions.RemoveEmptyEntries);
            if (values.Length != 3)
            {
                identifier = shortedTime = credSuffix = string.Empty;
                return false;
            }

            identifier = values[0];
            shortedTime = values[1];
            credSuffix = values[2];
            return true;
        }

        private static bool TryParseSignedHeaders(string headers, out string signedHeaders)
        {
            var parts = headers.Split(new[] {'='}, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2)
            {
                signedHeaders = string.Empty;
                return false;
            }

            signedHeaders = parts[1];
            return true;
        }

        private static bool TryParseSignature(string sig, out string signature)
        {
            var parts = sig.Split(new[] {'='}, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2)
            {
                signature = string.Empty;
                return false;
            }

            signature = parts[1];
            return true;
        }
    }
}