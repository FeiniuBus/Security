using System.Text;
using System.Text.RegularExpressions;

namespace FeiniuBus.Security.Signer
{
    internal static class Constants
    {
        public const string Scheme = "FNBUS1";
        public const string Algorithm = "HMAC-SHA256";

        public const string FeiniuBus1AlgorithmTag = Scheme + "-" + Algorithm;

        public const string Iso8601BasicDateTimeFormat = "yyyyMMddTHHmmssZ";
        public const string Iso8601BasicDateFormat = "yyyyMMdd";

        public const string Terminator = "feiniubus_request";
        public static readonly byte[] TerminatorBytes = Encoding.UTF8.GetBytes(Terminator);

        public const string Credential = "Credential";
        public const string SignedHeaders = "SignedHeaders";
        public const string Signature = "Signature";

        public const string EmptyBodySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        
        public static readonly Regex CompressWhitespaceRegex = new Regex("\\s+");
    }
}