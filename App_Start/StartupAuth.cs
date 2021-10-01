using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Claims;
using System.Threading.Tasks;
using System.Linq;
using System.Web;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using wgvmi15_net_core.Models;

namespace wgvmi15_net_core
{
    public partial class Startup
    {
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string appKey = ConfigurationManager.AppSettings["ida:ClientSecret"];
        private static string aadInstance = EnsureTrailingSlash(ConfigurationManager.AppSettings["ida:AADInstance"]);
        private static string authority =  aadInstance + "common"; 
        private ApplicationDbContext db = new ApplicationDbContext();

        // Esta é a ID do recurso da API do AAD Graph. Precisamos dela para solicitar um token para chamar a API do Graph.
        private static string graphResourceId = "https://graph.windows.net";

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions { });

            // em vez de usar a validação padrão (validando com base em um valor de emissor único, como fazemos em aplicativos de linha de negócios),
            // inserimos nossa própria lógica de validação multilocatário
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = clientId,
                    Authority = authority,
                    TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        // Se o aplicativo precisa acessar toda a organização, então adicione a lógica
                        // de validação do Emissor aqui.
                        // IssuerValidator
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                         SecurityTokenValidated = (context) =>
                        {
                            // Se sua lógica de autenticação for baseada nos usuários
                            return Task.FromResult(0);
                        },
                        AuthorizationCodeReceived = (context) =>
                        {
                            var code = context.Code;

                            ClientCredential credential = new ClientCredential(clientId, appKey);
                            string tenantID = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;
                            string signedInUserID = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;

                            AuthenticationContext authContext = new AuthenticationContext(aadInstance + tenantID, new ADALTokenCache(signedInUserID));
                            AuthenticationResult result = authContext.AcquireTokenByAuthorizationCodeAsync(
                                code, new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path)), credential, graphResourceId).Result;

                            return Task.FromResult(0);
                        }
                    }
                });

            // Isso faz com que qualquer middleware definido acima desta linha, executado antes da Regra de autorização, seja aplicado ao web.config
            app.UseStageMarker(PipelineStage.Authenticate);
        }

        private static string EnsureTrailingSlash(string value)
        {
            if (value == null)
            {
                value = string.Empty;
            }

            if (!value.EndsWith("/", StringComparison.Ordinal))
            {
                return value + "/";
            }

            return value;
        }
    }
}
