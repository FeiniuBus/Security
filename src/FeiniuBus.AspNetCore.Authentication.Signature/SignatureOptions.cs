using System.Net.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;

namespace FeiniuBus.AspNetCore.Authentication.Signature
{
    public class SignatureOptions
    {
        /// <summary>
        /// 缓存实现
        /// </summary>
        public IMemoryCache Cache { get; set; }
        
        /// <summary>
        /// 设置在获取访问密钥的时候是否启用缓存
        /// </summary>
        public bool EnableCaching { get; set; }
        
        /// <summary>
        /// 用于与认证服务器通信的 HttpMessageHandler
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }
        
        /// <summary>
        /// 认证服务器终端地址
        /// </summary>
        public PathString Endpoint { get; set; }
    }
}