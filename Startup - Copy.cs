using System;
using System.Web;
using EPiServer.Cms.UI.AspNetIdentity;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;
using System.Threading.Tasks;
using EPiServer.ServiceLocation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;
using EPiServer.Security;

[assembly: OwinStartup(typeof(EpiserverSite1.Startup))]

namespace EpiserverSite1
{
    public class StartupCopy
    {
        // <add key="ida:AADInstance" value="https://login.microsoftonline.com/{0}" />
        private static readonly string aadInstance = "https://identity.hawservers.com";

        // <add key="ida:ClientId" value="Client ID from Azure AD application" />
        private static string clientId = "0oa4j67yomOtwEGd32p7";

        // <add key="ida:PostLogoutRedirectUri" value="https://the logout post uri/" />
        private static readonly string postLogoutRedirectUri = "https://identity.hawservers.com/login/signout";
        // application id, or common for multi-tenant applications
        // <add key="ida:Authority" value="common" />
     //   private static readonly string authority = ConfigurationManager.AppSettings["ida:Authority"];

        private static string aadAuthority = "https://identity.hawservers.com/oauth2/aus4j6hlzlVZzXsj42p7/v1/authorize";

            //string.Format(CultureInfo.InvariantCulture, aadInstance, authority);

        const string LogoutPath = "/logout";

        public void Configuration(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = clientId,
                Authority = aadAuthority,
                PostLogoutRedirectUri = postLogoutRedirectUri,
                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    RoleClaimType = ClaimTypes.Role
                },
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = context =>
                    {
                        context.HandleResponse();
                        context.Response.Write(context.Exception.Message);
                        return Task.FromResult(0);
                    },
                    RedirectToIdentityProvider = context =>
                    {
                        // Here you can change the return uri based on multisite
                        HandleMultiSiteReturnUrl(context);

                        // To avoid a redirect loop to the federation server send 403 
                        // when user is authenticated but does not have access
                        if (context.OwinContext.Response.StatusCode == 401 &&
                            context.OwinContext.Authentication.User.Identity.IsAuthenticated)
                        {
                            context.OwinContext.Response.StatusCode = 403;
                            context.HandleResponse();
                        }
                        //XHR requests cannot handle redirects to a login screen, return 401
                        if (context.OwinContext.Response.StatusCode == 401 && IsXhrRequest(context.OwinContext.Request))
                        {
                            context.HandleResponse();
                        }
                        return Task.FromResult(0);
                    },
                    SecurityTokenValidated = (ctx) =>
                    {
                        var redirectUri = new Uri(ctx.AuthenticationTicket.Properties.RedirectUri,
                            UriKind.RelativeOrAbsolute);
                        if (redirectUri.IsAbsoluteUri)
                        {
                            ctx.AuthenticationTicket.Properties.RedirectUri = redirectUri.PathAndQuery;
                        }

                        //Sync user and the roles to EPiServer in the background
                        ServiceLocator.Current.GetInstance<ISynchronizingUserService>()
                            .SynchronizeAsync(ctx.AuthenticationTicket.Identity);
                        return Task.FromResult(0);
                    }
                }
            });
            app.UseStageMarker(PipelineStage.Authenticate);
            app.Map(LogoutPath, map =>
            {
                map.Run(context =>
                {
                    context.Authentication.SignOut();
                    return Task.FromResult(0);
                });
            });
        }

        private void HandleMultiSiteReturnUrl(
            RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            // here you change the context.ProtocolMessage.RedirectUri to corresponding siteurl
            // this is a sample of how to change redirecturi in the multi-tenant environment
            if (context.ProtocolMessage.RedirectUri == null)
            {
                var currentUrl = HttpContext.Current.Request.Url;
                context.ProtocolMessage.RedirectUri = new UriBuilder(
                    currentUrl.Scheme,
                    currentUrl.Host,
                    currentUrl.Port).ToString();
            }
        }

        private static bool IsXhrRequest(IOwinRequest request)
        {
            const string xRequestedWith = "X-Requested-With";

            var query = request.Query;
            if ((query != null) && (query[xRequestedWith] == "XMLHttpRequest"))
            {
                return true;
            }

            var headers = request.Headers;
            return (headers != null) && (headers[xRequestedWith] == "XMLHttpRequest");
        }
        /*
        public void Configuration(IAppBuilder app)
        {

            // Add CMS integration for ASP.NET Identity
            app.AddCmsAspNetIdentity<ApplicationUser>();

            // Remove to block registration of administrators
            app.UseAdministratorRegistrationPage(() => HttpContext.Current.Request.IsLocal);

            // Use cookie authentication
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString(Global.LoginPath),
                Provider = new CookieAuthenticationProvider
                {
                    // If the "/util/login.aspx" has been used for login otherwise you don't need it you can remove OnApplyRedirect.
                    OnApplyRedirect = cookieApplyRedirectContext =>
                    {
                        app.CmsOnCookieApplyRedirect(cookieApplyRedirectContext, cookieApplyRedirectContext.OwinContext.Get<ApplicationSignInManager<ApplicationUser>>());
                    },

                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager<ApplicationUser>, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => manager.GenerateUserIdentityAsync(user))
                }
            });
        }*/
    }
}
