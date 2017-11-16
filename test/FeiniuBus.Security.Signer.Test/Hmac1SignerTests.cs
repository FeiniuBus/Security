using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using Xunit;

namespace FeiniuBus.Security.Signer.Test
{
    public class Hmac1SignerTests
    {
        [Fact]
        public void TestSign()
        {
            var signer = new FeiniuBus1HmacSigner();
            var res = signer.Sign(BuildSigningContext());
        }
        
        private static SigningContext BuildSigningContext()
        {
            var body = new Body
            {
                Name = "xqlun",
                Age = 31
            };

            var data = JsonConvert.SerializeObject(body);

            var ctx = new SigningContext
            {
                Endpoint = new Uri("https://dc.feiniubus.com:5100/fns/v1/test/update"),
                Method = "PUT",
                Query = new Dictionary<string, string>
                {
                    {"id", "1232232"}
                },
                Body = Encoding.UTF8.GetBytes(data),
                Identifier = "AKID",
                Key = "SECRET"
            };

            ctx.Header = new Dictionary<string, string>
            {
                {"Content-Type", "application/json"},
                {"Content-Length", ctx.Body.Length.ToString()},
                {"Accept", "application/json"}
            };

            return ctx;
        }
    }

    public class Body
    {
        public string Name { get; set; }
        
        public int Age { get; set; }
    }
}