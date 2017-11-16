using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using FeiniuBus.Security.Signer.Util;

namespace FeiniuBus.Security.Signer
{
    public class FeiniuBus1HmacSigner : AbstractHmacSigner
    {
        private const string Scheme = "FNBUS1";
        private const string Algorithm = "HMAC-SHA256";

        private const string FeiniuBus1AlgorithmTag = Scheme + "-" + Algorithm;

        private const string Iso8601BasicDateTimeFormat = "yyyyMMddTHHmmssZ";
        private const string Iso8601BasicDateFormat = "yyyyMMdd";

        private const string Terminator = "feiniubus_request";
        private static readonly byte[] TerminatorBytes = Encoding.UTF8.GetBytes(Terminator);

        private const string Credential = "Credential";
        private const string SignedHeaders = "SignedHeaders";
        private const string Signature = "Signature";

        private const string EmptyBodySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        private static readonly Regex CompressWhitespaceRegex = new Regex("\\s+");
        
        public override HmacSigningResult Sign(SigningContext ctx)
        {
            throw new NotImplementedException();
        }

        private HmacSigningResult SignRequest(SigningContext ctx)
        {
            var result = new HmacSigningResult();
            if (ctx.Header.ContainsKey(HeaderKeys.HostHeader))
            {
                ctx.Header.Remove(HeaderKeys.HostHeader);
            }
            var hostHeader = ctx.Endpoint.Host;
            if (!ctx.Endpoint.IsDefaultPort)
            {
                hostHeader += ":" + ctx.Endpoint.Port;
            }
            ctx.Header.Add(HeaderKeys.HostHeader, hostHeader);
            result.Headers.Add(HeaderKeys.HostHeader, ctx.Header[HeaderKeys.HostHeader]);
            
            var signedAt = InitializeHeaders(result);
            var credentialString = BuildCredentialString(signedAt);
            var bodyHash = SetRequestBodyHash(ctx.Body);
            
            var sortedHeaders = SortAndPruneHeaders(ctx.Header);
            var canonicalizedHeaderNames = CanonicalizeHeaderNames(sortedHeaders);

            var parametersToCanonicalize = GetParametersToCanonicalize(ctx.Query);
            var canonicalQueryParams = CanonicalizeQueryParameters(parametersToCanonicalize);

            var canonicalRequest =
                CanonicalizeRequest(ctx.Endpoint, ctx.Method, sortedHeaders, canonicalQueryParams, bodyHash);

            var signature = ComputeSignature(ctx.Identifier, ctx.Key, signedAt, credentialString,
                canonicalizedHeaderNames, canonicalRequest);

            result.Signature = signature;
            var authorizationHeader = new StringBuilder();
            authorizationHeader.Append(FeiniuBus1AlgorithmTag);
            authorizationHeader.AppendFormat(" {0}={1}/{2},", Credential, ctx.Identifier, credentialString);
            authorizationHeader.AppendFormat("{0}={1},", SignedHeaders, canonicalizedHeaderNames);
            authorizationHeader.AppendFormat("{0}={1}", Signature, signature);
            result.Headers.Add(HeaderKeys.AuthorizationHeader, authorizationHeader.ToString());

            return result;
        }

        private static string ComputeSignature(string identifier, string key, DateTime signedAt,
            string credentialString, string signedHeaders, string canonicalRequest)
        {
            var dateStamp = signedAt.ToString(Iso8601BasicDateFormat, CultureInfo.InvariantCulture);



            var stringToSignBuilder = new StringBuilder();
            stringToSignBuilder.AppendFormat(CultureInfo.InvariantCulture, "{0}-{1}\n{2}\n{3}\n",
                Scheme,
                Algorithm,
                signedAt.ToString(Iso8601BasicDateTimeFormat, CultureInfo.InvariantCulture),
                credentialString);

            var canonicalRequestHashBytes = ComputeHash(canonicalRequest);
            stringToSignBuilder.Append(Hex.EncodeToString(canonicalRequestHashBytes, true));

            var skey = ComposeSigningKey(key, dateStamp);
            var stringToSign = stringToSignBuilder.ToString();
            var signature = ComputeKeyedHash(SigningAlgorithm.HmacSHA256, skey, stringToSign);
            return Hex.EncodeToString(signature, true);
        }

        private static byte[] ComposeSigningKey(string key, string date)
        {
            char[] ksecret = null;

            try
            {
                ksecret = (Scheme + key).ToCharArray();

                var hashDate = ComputeKeyedHash(SigningAlgorithm.HmacSHA256, Encoding.UTF8.GetBytes(ksecret),
                    Encoding.UTF8.GetBytes(date));
                return ComputeKeyedHash(SigningAlgorithm.HmacSHA256, hashDate, TerminatorBytes);
            }
            finally
            {
                if (ksecret != null)
                {
                    Array.Clear(ksecret, 0, ksecret.Length);
                }
            }
        }

        private static string BuildCredentialString(DateTime signedAt)
        {
            var credentialStringBuilder = new StringBuilder();
            credentialStringBuilder.AppendFormat("{0}/{1}",
                signedAt.ToString(Iso8601BasicDateFormat, CultureInfo.InvariantCulture), Terminator);

            return credentialStringBuilder.ToString();
        }

        private static string CanonicalizeRequest(Uri endpoint, string httpMethod,
            IDictionary<string, string> sortedHeaders, string canonicalQueryString, string bodyHash)
        {
            var canonicalRequest = new StringBuilder();
            canonicalRequest.AppendFormat("{0}\n", httpMethod);
            canonicalRequest.AppendFormat("{0}\n", endpoint.AbsolutePath);
            canonicalRequest.AppendFormat("{0}\n", canonicalQueryString);
            canonicalRequest.AppendFormat("{0}\n", CanonicalizeHeaders(sortedHeaders));
            canonicalRequest.AppendFormat("{0}\n", CanonicalizeHeaderNames(sortedHeaders));

            if (bodyHash != null)
            {
                canonicalRequest.Append(bodyHash);
            }

            return canonicalRequest.ToString();
        }

        private static string CanonicalizeHeaderNames(IEnumerable<KeyValuePair<string, string>> sortedHeaders)
        {
            var builder = new StringBuilder();
            foreach (var entry in sortedHeaders)
            {
                if (builder.Length > 0)
                {
                    builder.Append(";");
                }
                builder.Append(entry.Key.ToLowerInvariant());
            }

            return builder.ToString();
        }

        private static string CanonicalizeHeaders(IEnumerable<KeyValuePair<string, string>> sortedHeaders)
        {
            if (sortedHeaders == null || !sortedHeaders.Any())
            {
                return string.Empty;
            }
            
            var builder = new StringBuilder();
            foreach (var entry in sortedHeaders)
            {
                builder.Append(entry.Key.ToLowerInvariant());
                builder.Append(":");
                builder.Append(CompressSpaces(entry.Value));
                builder.Append("\n");
            }

            return builder.ToString();
        }

        private static IDictionary<string, string> SortAndPruneHeaders(
            IEnumerable<KeyValuePair<string, string>> requestHeaders)
        {
            var sortedHeaders = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var header in requestHeaders)
            {
                sortedHeaders.Add(header.Key, header.Value);
            }
            return sortedHeaders;
        }

        private static string SetRequestBodyHash(byte[] body)
        {
            if (body == null || body.Length == 0)
            {
                return EmptyBodySha256;
            }

            var hashed = CryptoUtilFactory.CryptoInstance.ComputeSha256Hash(body);
            return Hex.EncodeToString(hashed, true);
        }

        private static string CompressSpaces(string data)
        {
            if (data == null || !data.Contains(" "))
            {
                return data;
            }

            return CompressWhitespaceRegex.Replace(data, " ");
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

        private static DateTime InitializeHeaders(HmacSigningResult result)
        {
            var dt = DateTime.UtcNow;
            result.Headers.Add(HeaderKeys.XFeiniuBusDateHeader,
                dt.ToString(Iso8601BasicDateTimeFormat, CultureInfo.InvariantCulture));
            return dt;
        }
    }
}