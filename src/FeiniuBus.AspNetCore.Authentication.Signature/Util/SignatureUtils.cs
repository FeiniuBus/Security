using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace FeiniuBus.AspNetCore.Authentication.Signature.Util
{
    internal static class SignatureUtils
    {
        public const string Iso8601BasicDateTimeFormat = "yyyyMMddTHHmmssZ";
        private const string Slash = "/";
        private const char SlashChar = '/';
        
        /// <summary>
        ///     The Set of accepted and valid Url characters per RFC3986.
        ///     Characters outside of this set will be encoded.
        /// </summary>
        private const string ValidUrlCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

        /// <summary>
        ///     The Set of accepted and valid Url characters per RFC1738.
        ///     Characters outside of this set will be encoded.
        /// </summary>
        private const string ValidUrlCharactersRfc1738 =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";
        
        internal static readonly Dictionary<int, string> RfcEncodingSchemes = new Dictionary<int, string>
        {
            {3986, ValidUrlCharacters},
            {1738, ValidUrlCharactersRfc1738}
        };

        /// <summary>
        ///     The set of accepted and valid Url path characters per RFC3986.
        /// </summary>
        private static readonly string ValidPathCharacters = DetermineValidPathCharacters();
        
        // Checks which path characters should not be encoded
        // This set will be different for .NET 4 and .NET 4.5, as
        // per http://msdn.microsoft.com/en-us/library/hh367887%28v=vs.110%29.aspx
        private static string DetermineValidPathCharacters()
        {
            const string basePathCharacters = "/:'()!*[]$";

            var sb = new StringBuilder();
            foreach (var c in basePathCharacters)
            {
                var escaped = Uri.EscapeUriString(c.ToString());
                if (escaped.Length == 1 && escaped[0] == c)
                    sb.Append(c);
            }
            return sb.ToString();
        }

        public static string ToHex(byte[] data, bool lowercase)
        {
            var sb = new StringBuilder();

            for (var i = 0; i < data.Length; i++)
                sb.Append(data[i].ToString(lowercase ? "x2" : "X2", CultureInfo.InvariantCulture));

            return sb.ToString();
        }

        /// <summary>
        ///     Convert a hex string to bytes
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public static byte[] HexStringToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex) || hex.Length % 2 == 1)
                throw new ArgumentOutOfRangeException(nameof(hex));

            var count = 0;
            var buffer = new byte[hex.Length / 2];
            for (var i = 0; i < hex.Length; i += 2)
            {
                var sub = hex.Substring(i, 2);
                var b = Convert.ToByte(sub, 16);
                buffer[count] = b;
                count++;
            }

            return buffer;
        }

        public static string CanonicalizeResourcePath(string resourcePath)
        {
            if (string.IsNullOrEmpty(resourcePath))
                return Slash;

            var pathSegments = resourcePath.Split(new[] {SlashChar}, StringSplitOptions.None);

            var encodedSegments = pathSegments.Select(segment => UrlEncode(segment, false)).ToArray();

            var canonicalizedResourcePath = string.Join(Slash, encodedSegments);

            return canonicalizedResourcePath;
        }

        public static string UrlEncode(string data, bool path)
        {
            return UrlEncode(3986, data, path);
        }

        public static string UrlEncode(int rfcNumber, string data, bool path)
        {
            var encoded = new StringBuilder(data.Length * 2);
            string validUrlCharacters;
            if (!RfcEncodingSchemes.TryGetValue(rfcNumber, out validUrlCharacters))
                validUrlCharacters = ValidUrlCharacters;

            var unreservedChars = string.Concat(validUrlCharacters, path ? ValidPathCharacters : "");

            foreach (char symbol in Encoding.UTF8.GetBytes(data))
                if (unreservedChars.IndexOf(symbol) != -1)
                    encoded.Append(symbol);
                else
                    encoded.Append("%").Append(string.Format(CultureInfo.InvariantCulture, "{0:X2}", (int) symbol));

            return encoded.ToString();
        }
    }
}