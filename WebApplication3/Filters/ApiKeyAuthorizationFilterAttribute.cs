using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Configuration;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace WebApplication3.Filters
{
    public class ApiKeyAuthorizationFilterAttribute : AuthorizationFilterAttribute
    {
        public const string HeaderName = "X-ApiKey";


        public override void OnAuthorization(HttpActionContext actionContext)
        {
            IEnumerable<string> securityKeys;
            var key = ConfigurationManager.AppSettings["ApiKey"];

            if (string.IsNullOrWhiteSpace(key) ||
                !actionContext.Request.Headers.TryGetValues(HeaderName, out securityKeys) ||
                securityKeys.First() != key)
            {
                actionContext.Response = new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    ReasonPhrase = "Invalid Security Key",
                    Content = new StringContent("Invalid Security Key")
                };
                return;
            }

            base.OnAuthorization(actionContext);
        }
    }
}