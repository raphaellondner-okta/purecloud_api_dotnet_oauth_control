using System;
using System.Linq;
using System.Net;
using System.Web;
using System.Windows.Forms;
using RestSharp;
using RestSharp.Authenticators;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Protocols;
using System.Threading.Tasks;

namespace ININ.PureCloud.OAuthControl
{
    public class OAuthWebBrowser : WebBrowser
    {
        #region Private Members
        private string _accessToken;
        private string _idToken;
        private OpenIdConnectConfiguration _config;
        #endregion

        #region Public Members

        /// <summary>
        /// Use a static property from PureCloudEnvironment to set the environment
        /// If used with Okta, set to the sub-domain of your Okta organization (e.g. "company.okta.com" if your Okta organization url is "https://company.okta.com")
        /// </summary>
        public string Environment { get; set; }

        /// <summary>
        /// The redirect URI for the OAuth Client
        /// </summary>
        public string RedirectUri { get; set; }

        /// <summary>
        /// [True] if the redirect URI does not resolve. Setting this to true will hide the control when the redirect URI is encountered.
        /// </summary>
        public bool RedirectUriIsFake { get; set; }

        /// <summary>
        /// The OAuth Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// The OAuth Client Secret. Only used with an authorization code grant.
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Dynamic value that should be identical to the one available in the authorize response (as fragment) 
        /// </summary>
        public string State { get; set; }

        /// <summary>
        /// Dynamic value that should be identical to the one available in the returned ID token
        /// </summary>
        public string Nonce { get; set; }

        /// <summary>
        /// The Access Token returned after authenticating.
        /// </summary>
        public string AccessToken
        {
            get { return _accessToken; }
            private set
            {
                if (value == _accessToken) return;

                _accessToken = value;
                RaiseAuthenticated(AccessToken);
            }
        }

        /// <summary>
        /// The number of seconds in which the token expires. This will be 0 if the value is unknown.
        /// </summary>
        public int TokenExpiresInSeconds { get; private set; }

        /// <summary>
        /// The OpenID Connect scopes requested by the client
        /// </summary>
        public string Scopes { get; set; }

        /// <summary>
        /// The response_type parameter for the OIDC authorization call ("id_token", "token" or "id_token token")
        /// </summary>
        public string ResponseType { get; set; }

        /// <summary>
        /// The ID Token returned after authenticating.
        /// </summary>
        public string IDToken
        {
            get { return _idToken; }
            private set
            {
                if (value == _idToken) return;

                _idToken = value;
                RaiseAuthenticated(IDToken);
            }
        }

        public List<Claim> IDClaims { get; private set; }

        public OpenIdConnectConfiguration OpenIdConfig { get; set; }

        public delegate void ExceptionEncounteredDelegate(string source, Exception ex);

        public delegate void AuthenticatedDelegate(string accessToken);

        /// <summary>
        /// Raised when an exception occurs during the authentication process
        /// </summary>
        public event ExceptionEncounteredDelegate ExceptionEncountered;

        /// <summary>
        /// Raised when an Access Token is successfully retrieved
        /// </summary>
        public event AuthenticatedDelegate Authenticated;

        #endregion

        public OAuthWebBrowser()
        {
            RedirectUriIsFake = false;
            Environment = "mypurecloud.com";

            this.Navigated += OnNavigated;
        }

        #region Private Methods
        private void RaiseExceptionEncountered(string source, Exception ex)
        {
            ExceptionEncountered?.Invoke(source, ex);
        }

        private void RaiseAuthenticated(string accessToken)
        {
            Authenticated?.Invoke(accessToken);
        }

        /// <summary>
        /// Loads the OpendID Configuration from the Okta endpoint
        /// </summary>
        /// <returns></returns>
        internal async Task<OpenIdConnectConfiguration> LoadOpenIdConnectConfigurationAsync()
        {
            if (_config == null)
            {
                var discoAddress = "https://" + Environment + "/.well-known/openid-configuration";

                var manager = new ConfigurationManager<OpenIdConnectConfiguration>(discoAddress);
                _config = await manager.GetConfigurationAsync();
            }
            return _config;
        }

        private void OnNavigated(object sender, WebBrowserNavigatedEventArgs args)
        {
            try
            {
                // Ignore the navigated event after we have an access token
                if (!string.IsNullOrEmpty(AccessToken)) return;

                // Check for errors
                if (args.Url.Fragment.StartsWith("#/error?"))
                {
                    // Strip leading part of path and parse
                    var errorFragment = HttpUtility.ParseQueryString(args.Url.Fragment.Substring(8));

                    // Check for errorKey parameter
                    if (errorFragment.AllKeys.Contains("errorKey"))
                    {
                        RaiseExceptionEncountered("OAuthWebBrowser.Navigated", new Exception(errorFragment["errorKey"]));
                        return;
                    }
                }

                // Process our redirect URL
                if (args.Url.ToString().ToLowerInvariant().StartsWith(RedirectUri.ToLowerInvariant()))
                {
                    //var queryString = HttpUtility.ParseQueryString(args.Url.Query);

                    var fragment = HttpUtility.ParseQueryString(args.Url.Fragment.TrimStart('#'));
                    
                    //OIDC state validation
                    if (fragment.AllKeys.Contains("state"))
                    {
                        if (fragment["state"] != State)
                        {
                            //if we have the wrong state from the response, let's stop processing anything else
                            return;
                        }
                    }

                    // Get the token from the redirect URI (implicit grant)
                    if (fragment.AllKeys.Contains("expires_in"))
                    {
                        var i = 0;
                        if (int.TryParse(fragment["expires_in"], out i))
                            TokenExpiresInSeconds = i;
                    }
                    if (fragment.AllKeys.Contains("access_token"))
                    {
                        AccessToken = fragment["access_token"];
                        if (RedirectUriIsFake) Visible = false;
                    }
                    if (fragment.AllKeys.Contains("id_token"))
                    {
                        IDToken = fragment["id_token"];
                        if (RedirectUriIsFake) Visible = false;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                RaiseExceptionEncountered("OAuthWebBrowser.OnNavigated", ex);
            }

            if (ResponseType.Contains("id_token") && !string.IsNullOrEmpty(IDToken))
            {
                var idClaims = ValidateIdentityToken(IDToken); 

                if (idClaims != null)
                {
                    //OIDC nonce validation
                    var nonce = idClaims.FirstOrDefault(c => c.Type == "nonce");

                    if (nonce != null && string.Equals(nonce.Value, Nonce, StringComparison.Ordinal))
                    {
                        //we only set the IDClaims property if the nonce is valid
                        IDClaims = idClaims;
                    }
                }
            }
        }
        /// <summary>
        /// Performs audience, issuer and signing key OpenID Connect validation
        /// </summary>
        /// <param name="identityToken">OpenID Connect ID Token</param>
        /// <returns>the list of claims extracted from the ID Token</returns>
        private List<Claim> ValidateIdentityToken(string identityToken)
        {
            var tokens = OpenIdConfig.SigningTokens;

            var parameter = new TokenValidationParameters
            {
                ValidIssuer = OpenIdConfig.Issuer,
                ValidAudience = this.ClientId,
                ValidateIssuerSigningKey = true,
                IssuerSigningTokens = tokens
            };

            JwtSecurityTokenHandler.InboundClaimTypeMap.Clear();
            var handler = new JwtSecurityTokenHandler();

            SecurityToken token;
            try
            {
                return handler.ValidateToken(identityToken, parameter, out token).Claims.ToList();
            }
            catch
            {
                return null;
            }
        }
        #endregion

        #region Public Methods


        /// <summary>
        /// Initiates the Implicit Grant OAuth flow
        /// </summary>
        /// <param name="bUseOkta">Use to craft an Okta-compatible Authorize url</param>
        public void BeginImplicitGrant(bool bUseOkta = false)
        {
            // Clear existing token
            AccessToken = "";

            string strAuthorizeUrl = $"https:\\\\login.{Environment}/authorize?client_id={ClientId}&response_type=token&redirect_uri={RedirectUri}";
            if (bUseOkta)
            {
                strAuthorizeUrl = $"https:\\\\{Environment}/oauth2/v1/authorize?client_id={ClientId}&response_type={ResponseType}&redirect_uri={RedirectUri}&scope={Scopes}&response_mode=fragment&state={State}&nonce={Nonce}";
            }

            // Navigate to the login URL
            this.Navigate(strAuthorizeUrl);
        }

        #endregion
    }
}