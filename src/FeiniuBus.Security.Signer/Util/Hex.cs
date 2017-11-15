using System.Globalization;
using System.Text;

namespace FeiniuBus.Security.Signer.Util
{
    internal static class Hex
    {
        public static string EncodeToString(byte[] data, bool lowercase)
        {
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString(lowercase ? "x2" : "X2", CultureInfo.InvariantCulture));
            }

            return sb.ToString();
        }
    }
}