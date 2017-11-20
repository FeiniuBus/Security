using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Xunit;

namespace FeiniuBus.Security.Signer.Test
{
    public class Hmac1SignerTests
    {
        [Fact]
        public async Task TestSign()
        {
            var builder = new WebHostBuilder().ConfigureServices(services =>
            {
                services.AddLogging();
            }).Configure(app =>
            {
                app.Run(async ctx =>
                {
                    var loggerFactory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
                    var validator = new FeiniuBus1HmacValidator(loggerFactory, key => "SECRET");
                    
                    var verfingCtx = new VerifingContext
                    {
                        Method = ctx.Request.Method,
                        Path = ctx.Request.Path,
                        Query = ctx.Request.Query,
                        Header = ctx.Request.Headers,
                        
                    };

                    var reader = new StreamReader(ctx.Request.Body);
                    var reqBody = await reader.ReadToEndAsync().ConfigureAwait(false);

                    verfingCtx.Body = Encoding.UTF8.GetBytes(reqBody);
                    Assert.True(validator.Verify(verfingCtx));
                    
                    await ctx.Response.WriteAsync("Hello World");
                });
            });

            var server = new TestServer(builder);
            var body = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new Body {Name = "xqlun", Age = 31}));

            var req = new HttpRequestMessage(HttpMethod.Put,
                "https://dc.feiniubus.com:5100/fns/v1/test/update?id=1232232");
            req.Headers.Add("Accept", "application/json");

            req.Content = new ByteArrayContent(body);
            req.Content.Headers.Add("Content-Type", "application/json");
            req.Content.Headers.Add("Content-Length", body.Length.ToString());

            var signingCtx = new SigningContext
            {
                Body = body,
                Endpoint = req.RequestUri,
                Identifier = "AKID",
                Key = "SECRET",
                Method = req.Method.ToString(),
                Query = new Dictionary<string, string>
                {
                    {"id", "1232232"}
                }
            };

            foreach (var reqHeader in req.Headers)
            {
                signingCtx.Header.Add(reqHeader.Key, reqHeader.Value.First());
            }
            foreach (var header in req.Content.Headers)
            {
                signingCtx.Header.Add(header.Key, header.Value.First());
            }
            
            var res = new FeiniuBus1HmacSigner().Sign(signingCtx);
            foreach (var header in res.Headers)
            {
                req.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            await server.CreateClient().SendAsync(req).ConfigureAwait(false);
        }
    }

    public class Body
    {
        public string Name { get; set; }
        
        public int Age { get; set; }
    }
}