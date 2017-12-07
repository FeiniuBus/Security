using System;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace FeiniuBus.AspNetCore.Authentication.Enterprise
{
    public class EnterpriseAuthenticationHandler : AuthenticationHandler<EnterpriseAuthenticationOptions>
    {
        private const string FeiniuBusAccessKeyHeader = "x-feiniubus-accesskey";
        private const string UserCachePrefix = "EnterpriseUser";
        
        public EnterpriseAuthenticationHandler(IOptionsMonitor<EnterpriseAuthenticationOptions> options,
            ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        protected HttpClient Backchannel => Options.BackChannel;

        protected IMemoryCache Cache => Options.Cache;

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Context.Request.Headers.TryGetValue(FeiniuBusAccessKeyHeader, out var accessKey))
            {
                Logger.LogWarning($"Header: {FeiniuBusAccessKeyHeader} not exists.");
                return await Task.FromResult(AuthenticateResult.NoResult());
            }

            var user = await GetUser(accessKey).ConfigureAwait(false);
            if (user == null || !user.IsSuccess)
            {
                return AuthenticateResult.NoResult();
            }

            return AuthenticateResult.Success(CreateTicket(user));
        }

        private AuthenticationTicket CreateTicket(UserApplicationAuthentication user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var id = new ClaimsIdentity(user.AuthenticationType, user.NameType, user.RoleType);
            foreach (var claim in user.Claims)
            {
                id.AddClaim(new Claim(claim.Key, claim.Value ?? string.Empty));
            }
            
            var principal = new ClaimsPrincipal(id);
            var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(),
                EnterpriseAuthenticationDefaults.AuthenticationScheme);
            
            Logger.LogInformation($"Authentication Success,Enterprise name is {user.Claims.FirstOrDefault(i => i.Key == ClaimTypes.NameIdentifier).Value}");
            return ticket;
        }

        private async Task<UserApplicationAuthentication> GetUser(string accessKey)
        {
            UserApplicationAuthentication model;
            if (Options.EnableCaching)
            {
                model = GetUserFromCache(accessKey);
                if (model != null)
                {
                    return model;
                }
            }

            model = await GetUserFromServer(accessKey).ConfigureAwait(false);
            if (model != null)
            {
                SetUserToCache(accessKey, model);
            }

            return model;
        }

        private UserApplicationAuthentication GetUserFromCache(string accessKey)
        {
            try
            {
                var key = GetLocalizedKey(accessKey);
                var data = Cache.Get<byte[]>(key);

                if (data == null)
                {
                    return null;
                }

                var model = JsonConvert.DeserializeObject<UserApplicationAuthentication>(
                    Encoding.UTF8.GetString(data, 0, data.Length));
                return model;
            }
            catch (Exception e)
            {
                Logger.LogError(899, e, "从缓存获取企业用户信息失败");
                return null;
            }
        }

        private void SetUserToCache(string accessKey, UserApplicationAuthentication model)
        {
            try
            {
                var memoryCacheEntryOptions =
                    new MemoryCacheEntryOptions {AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(300)};
                if (Options.AbsoluteExpirationRelativeToNow.HasValue)
                {
                    memoryCacheEntryOptions.AbsoluteExpirationRelativeToNow =
                        TimeSpan.FromSeconds(Options.AbsoluteExpirationRelativeToNow.Value);
                }

                var value = JsonConvert.SerializeObject(model);
                Cache.Set(GetLocalizedKey(accessKey), Encoding.UTF8.GetBytes(value), memoryCacheEntryOptions);
            }
            catch (Exception e)
            {
                Logger.LogError(899, e, "将企业用户信息写入缓存失败");
            }
        }

        private async Task<UserApplicationAuthentication> GetUserFromServer(string accessKey)
        {
            var builder = new UriBuilder(Options.Authority)
            {
                Query = QueryString.Create("accessKey", accessKey).Value
            };
            var req = new HttpRequestMessage(HttpMethod.Get, builder.Uri);
            var resp = await Backchannel.SendAsync(req).ConfigureAwait(false);

            try
            {
                resp.EnsureSuccessStatusCode();
                var model =
                    JsonConvert.DeserializeObject<UserApplicationAuthentication>(
                        await resp.Content.ReadAsStringAsync());

                return model;
            }
            catch (Exception e)
            {
                Logger.LogError(899, e, "未能正确识别企业账号信息");
                return null;
            }
        }

        private static string GetLocalizedKey(string accessKey)
        {
            return $"{UserCachePrefix}_{accessKey}";
        }
    }
}