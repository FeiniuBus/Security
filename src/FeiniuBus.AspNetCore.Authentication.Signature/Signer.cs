using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using FeiniuBus.AspNetCore.Authentication.Signature.Extensions;
using FeiniuBus.AspNetCore.Authentication.Signature.Util;
using Microsoft.AspNetCore.Http;

namespace FeiniuBus.AspNetCore.Authentication.Signature
{
    internal class Signer
    {
        private const SigningAlgorithm SigningAlgorithm = Util.SigningAlgorithm.HmacSha256;
        private const string Terminator = "feiniubus_request";
        private const string Algorithm = "HMAC-SHA256";
        private const string Scheme = "FNSIGN";
        private static readonly byte[] TerminatorBytes = Encoding.UTF8.GetBytes(Terminator);
        
        public static byte[] Sign(HttpRequest request, string accessKeyId, string secretAccessKey)
        {
            if (!request.Headers.TryGetValue(HeaderKeys.XFeiniuBusDateHeader, out var signAt))
            {
                return null;
            }
            
            var query = request.Query;
            var parametersToCanonicalize = GetParametersToCanonicalize(query.ToDictionary());
            var canonicalParameters = CanonicalizeQueryParameters(parametersToCanonicalize, true);
            var bodyHash = GetRequestBodyHash(request);

            var canonicalRequest = CanonicalizeRequest(request.Path, request.Method, canonicalParameters, bodyHash);

            return ComputeSignature(accessKeyId, secretAccessKey, signAt, canonicalRequest);
        }

        protected static byte[] ComputeSignature(string accessKeyId, string secretAccessKey, string signedAt,
            string canonicalRequest)
        {
            var stringToSignBuilder = new StringBuilder();
            stringToSignBuilder.AppendFormat(CultureInfo.InvariantCulture, "{0}-{1}\n{2}\n", Algorithm, signedAt,
                accessKeyId);

            var canonicalRequestHashBytes = ComputeHash(canonicalRequest);
            stringToSignBuilder.Append(SignatureUtils.ToHex(canonicalRequestHashBytes, true));

            var key = ComposeSigningKey(secretAccessKey, signedAt);

            var stringToSign = stringToSignBuilder.ToString();
            var signature = ComputeKeyedHash(SigningAlgorithm, key, stringToSign);
            return signature;
        }

        protected static string CanonicalizeRequest(string requestPath, string httpMethod,
            string queryString, string bodyHash)
        {
            var canonicalRequest = new StringBuilder();
            canonicalRequest.AppendFormat("{0}\n", httpMethod);
            canonicalRequest.AppendFormat("{0}\n", SignatureUtils.CanonicalizeResourcePath(requestPath));
            canonicalRequest.AppendFormat("{0}\n", queryString);

            if (bodyHash != null)
            {
                canonicalRequest.Append(bodyHash);
            }

            return canonicalRequest.ToString();
        }

        private static IDictionary<string, string> GetParametersToCanonicalize(IDictionary<string, string> queryParameters)
        {
            var parametersToCanonicalize = new Dictionary<string, string>();

            if (queryParameters != null && queryParameters.Count > 0)
            {
                foreach (var query in queryParameters.Where(query => query.Value != null))
                {
                    parametersToCanonicalize.Add(query.Key, query.Value);
                }
            }

            return parametersToCanonicalize;
        }

        protected static string CanonicalizeQueryParameters(IDictionary<string, string> parameters,
            bool uriEncodeParameters)
        {
            if (parameters == null || parameters.Count == 0)
            {
                return string.Empty;
            }

            var canonicalQueryString = new StringBuilder();
            var queryParams = new SortedDictionary<string, string>(parameters, StringComparer.Ordinal);
            foreach (var param in queryParams)
            {
                if (canonicalQueryString.Length > 0)
                {
                    canonicalQueryString.Append("&");
                }
                if (uriEncodeParameters)
                {
                    if (string.IsNullOrEmpty(param.Value))
                    {
                        canonicalQueryString.AppendFormat("{0}=", SignatureUtils.UrlEncode(param.Key, false));
                    }
                    else
                    {
                        canonicalQueryString.AppendFormat("{0}={1}", SignatureUtils.UrlEncode(param.Key, false),
                            SignatureUtils.UrlEncode(param.Value, false));
                    }
                }
                else
                {
                    if (string.IsNullOrEmpty(param.Value))
                        canonicalQueryString.AppendFormat("{0}=", param.Key);
                    else
                        canonicalQueryString.AppendFormat("{0}={1}", param.Key, param.Value);
                }
            }

            return canonicalQueryString.ToString();
        }
        
        private static byte[] ComputeHash(string data)
        {
            return ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        private static byte[] ComputeHash(byte[] data)
        {
            return CryptoUtilFactory.CryptoInstance.ComputeSha256Hash(data);
        }

        private static byte[] ComposeSigningKey(string secretAccessKey, string date)
        {
            char[] ksecret = null;

            try
            {
                ksecret = (Scheme + secretAccessKey).ToCharArray();

                var hashDate = ComputeKeyedHash(SigningAlgorithm, Encoding.UTF8.GetBytes(ksecret),
                    Encoding.UTF8.GetBytes(date));

                return ComputeKeyedHash(SigningAlgorithm, hashDate, TerminatorBytes);
            }
            finally
            {
                if (ksecret != null)
                    Array.Clear(ksecret, 0, ksecret.Length);
            }
        }

        private static byte[] ComputeKeyedHash(SigningAlgorithm algorithm, byte[] key, string data)
        {
            return ComputeKeyedHash(algorithm, key, Encoding.UTF8.GetBytes(data));
        }

        private static byte[] ComputeKeyedHash(SigningAlgorithm algorithm, byte[] key, byte[] data)
        {
            return CryptoUtilFactory.CryptoInstance.HmacSignBinary(data, key, algorithm);
        }
        
        private static string GetRequestBodyHash(HttpRequest request)
        {
            byte[] payloadBytes;
            if (request.Method == "GET" || request.Method == "DELETE" || request.Method == "HEAD")
            {
                payloadBytes = Encoding.UTF8.GetBytes(string.Empty); 
            }
            else
            {
                payloadBytes = GetRequestPayloadBytes(request);
            }
            
            var payloadHashBytes = CryptoUtilFactory.CryptoInstance.ComputeSha256Hash(payloadBytes);
            var computedContentHash = SignatureUtils.ToHex(payloadHashBytes, true);
            return computedContentHash;
        }

        private static byte[] GetRequestPayloadBytes(HttpRequest request)
        {
            if (request.Body.CanRead)
            {
                var reader = new StreamReader(request.Body);
                var body = reader.ReadToEnd();

                if (request.Body.CanSeek)
                    request.Body.Seek(0, SeekOrigin.Begin);

                return Encoding.UTF8.GetBytes(body);
            }

            return Encoding.UTF8.GetBytes(string.Empty);
        }
    }
}