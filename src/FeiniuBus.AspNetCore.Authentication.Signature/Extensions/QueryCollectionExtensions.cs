using System.Collections.Generic;
using Microsoft.AspNetCore.Http;

namespace FeiniuBus.AspNetCore.Authentication.Signature.Extensions
{
    public static class QueryCollectionExtensions
    {
        /// <summary>
        /// 将 IQueryCollection 转换为字典
        /// </summary>
        /// <param name="query"></param>
        /// <returns></returns>
        public static IDictionary<string, string> ToDictionary(this IQueryCollection query)
        {
            if (query == null || query.Count == 0)
                return null;

            var parameters = new Dictionary<string, string>();
            foreach (var pair in query)
                parameters.Add(pair.Key, pair.Value);
            return parameters;
        }
    }
}