using System.Collections.Generic;
using System.Security.Claims;

namespace FeiniuBus.AspNetCore.Authentication.Enterprise
{
    internal class UserApplicationAuthentication
    {
        public bool IsSuccess { get; set; }
        public string AuthenticationType { get; set; } = "Enterprise";
        public string NameType { get; set; } = ClaimTypes.Name;
        public string RoleType { get; set; } = ClaimTypes.Role;
        public IDictionary<string, string> Claims { get; set; } = new Dictionary<string, string>();
    }
}