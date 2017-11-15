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

        private const string Terminator = "feiniubus_request";
        private static readonly byte[] TerminatorBytes = Encoding.UTF8.GetBytes(Terminator);

        private const string Credential = "Credential";
        private const string SignedHeaders = "SignedHeaders";
        private const string Signature = "Signature";

        private const string EmptyBodySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        private static readonly Regex CompressWhitespaceRegex = new Regex("\\s+");
        
        public override HmacSigningResult Sign(Uri endpoint, byte[] body, IDictionary<string, string> header, IDictionary<string, string> parameter, string identifier,
            string key)
        {
            throw new NotImplementedException();
        }

        private HmacSigningResult SignRequest()
        {
            var result = new HmacSigningResult();
            var signedAt = InitializeHeaders(result);

            return result;
        }

        private static string CanonicalizeRequest(Uri endpoint, string httpPath, string httpMethod,
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