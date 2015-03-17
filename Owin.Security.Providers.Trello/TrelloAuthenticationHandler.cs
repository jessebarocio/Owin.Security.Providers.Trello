using Microsoft.Owin;
using Microsoft.Owin.Helpers;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.Trello.Messages;
using Owin.Security.Providers.Trello.Provider;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Trello
{
    public class TrelloAuthenticationHandler : AuthenticationHandler<TrelloAuthenticationOptions>
    {
        // Used for generating OAuth Timestamp
        private static readonly DateTime Epoch = new DateTime( 1970, 1, 1, 0, 0, 0, DateTimeKind.Utc );
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private const string StateCookie = "_TrelloState";

        // Endpoints for OAuth tokens - see https://trello.com/docs/gettingstarted/oauth.html
        private const string RequestTokenEndpoint = "https://trello.com/1/OAuthGetRequestToken";
        private const string AuthenticationEndpoint = "https://trello.com/1/OAuthAuthorizeToken";
        private const string AccessTokenEndpoint = "https://trello.com/1/OAuthGetAccessToken";
        // Endpoint for retrieving user information
        private const string UserInfoEndpoint = "https://trello.com/1/members/me";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public TrelloAuthenticationHandler( HttpClient httpClient, ILogger logger )
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            if ( Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path )
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            try
            {
                IReadableStringCollection query = Request.Query;
                string protectedRequestToken = Request.Cookies[StateCookie];

                // Get request token
                RequestToken requestToken = Options.StateDataFormat.Unprotect( protectedRequestToken );
                if ( requestToken == null )
                {
                    _logger.WriteWarning( "Invalid state" );
                    return null;
                }

                properties = requestToken.Properties;

                // Verify response
                string returnedToken = query.Get( "oauth_token" );
                if ( string.IsNullOrWhiteSpace( returnedToken ) )
                {
                    _logger.WriteWarning( "Missing oauth_token" );
                    return new AuthenticationTicket( null, properties );
                }

                if ( returnedToken != requestToken.Token )
                {
                    _logger.WriteWarning( "Unmatched token" );
                    return new AuthenticationTicket( null, properties );
                }

                string oauthVerifier = query.Get( "oauth_verifier" );
                if ( string.IsNullOrWhiteSpace( oauthVerifier ) )
                {
                    _logger.WriteWarning( "Missing or blank oauth_verifier" );
                    return new AuthenticationTicket( null, properties );
                }

                // Get access token
                AccessToken accessToken = await ObtainAccessTokenAsync( Options.Key, Options.Secret, requestToken, oauthVerifier );

                // Get user information
                var userInfo = await GetUserInformationAsync( accessToken.Token );

                // Build context and ClaimsIdentity
                var context = new TrelloAuthenticatedContext( Context, userInfo, accessToken.Token, accessToken.TokenSecret );
                context.Identity = new ClaimsIdentity(
                    new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType),
                        new Claim(ClaimTypes.Name, context.Username, XmlSchemaString, Options.AuthenticationType),
                        new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType),
                        new Claim("urn:trello:id", context.Id, XmlSchemaString, Options.AuthenticationType),
                        new Claim("urn:trello:username", context.Username, XmlSchemaString, Options.AuthenticationType)
                    },
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType );
                context.Properties = requestToken.Properties;

                Response.Cookies.Delete( StateCookie );

                await Options.Provider.Authenticated( context );

                return new AuthenticationTicket( context.Identity, context.Properties );
            }
            catch ( Exception ex )
            {
                _logger.WriteError( "Authentication failed", ex );
                return new AuthenticationTicket( null, properties );
            }
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            if ( Response.StatusCode != 401 )
            {
                return;
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge( Options.AuthenticationType, Options.AuthenticationMode );

            if ( challenge != null )
            {
                string requestPrefix = String.Format( "{0}://{1}", Request.Scheme, Request.Host );
                string callBackUrl = requestPrefix + RequestPathBase + Options.CallbackPath;

                AuthenticationProperties extra = challenge.Properties;
                if ( string.IsNullOrEmpty( extra.RedirectUri ) )
                {
                    extra.RedirectUri = requestPrefix + Request.PathBase + Request.Path + Request.QueryString;
                }

                RequestToken requestToken = await ObtainRequestTokenAsync( Options.Key, Options.Secret, callBackUrl, extra );

                if ( requestToken.CallbackConfirmed )
                {
                    string trelloAuthenticationEndpoint = GetAuthenticationEndpoint( requestToken.Token );

                    var cookieOptions = new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = Request.IsSecure
                    };

                    Response.Cookies.Append( StateCookie, Options.StateDataFormat.Protect( requestToken ), cookieOptions );

                    var redirectContext = new TrelloApplyRedirectContext(
                        Context, Options,
                        extra, trelloAuthenticationEndpoint );
                    Options.Provider.ApplyRedirect( redirectContext );
                }
                else
                {
                    _logger.WriteError( "requestToken CallbackConfirmed!=true" );
                }
            }
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            AuthenticationTicket model = await AuthenticateAsync();
            if ( model == null )
            {
                _logger.WriteWarning( "Invalid return state, unable to redirect." );
                Response.StatusCode = 500;
                return true;
            }

            var context = new TrelloReturnEndpointContext( Context, model )
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = model.Properties.RedirectUri
            };
            model.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint( context );

            if ( context.SignInAsAuthenticationType != null && context.Identity != null )
            {
                ClaimsIdentity signInIdentity = context.Identity;
                if ( !string.Equals( signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal ) )
                {
                    signInIdentity = new ClaimsIdentity( signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType );
                }
                Context.Authentication.SignIn( context.Properties, signInIdentity );
            }

            if ( !context.IsRequestCompleted && context.RedirectUri != null )
            {
                if ( context.Identity == null )
                {
                    // add a redirect hint that sign-in failed in some way
                    context.RedirectUri = WebUtilities.AddQueryString( context.RedirectUri, "error", "access_denied" );
                }
                Response.Redirect( context.RedirectUri );
                context.RequestCompleted();
            }

            return context.IsRequestCompleted;
        }

        private async Task<RequestToken> ObtainRequestTokenAsync( string consumerKey, string consumerSecret, string callBackUri, AuthenticationProperties properties )
        {
            _logger.WriteVerbose( "ObtainRequestToken" );

            string nonce = Guid.NewGuid().ToString( "N" );

            var authorizationParts = new SortedDictionary<string, string>
            {
                { "oauth_callback", callBackUri },
                { "oauth_consumer_key", consumerKey },
                { "oauth_nonce", nonce },
                { "oauth_signature_method", "HMAC-SHA1" },
                { "oauth_timestamp", GenerateTimeStamp() },
                { "oauth_version", "1.0" }
            };

            var parameterBuilder = new StringBuilder();
            foreach ( var authorizationKey in authorizationParts )
            {
                parameterBuilder.AppendFormat( "{0}={1}&", Uri.EscapeDataString( authorizationKey.Key ), Uri.EscapeDataString( authorizationKey.Value ) );
            }
            parameterBuilder.Length--;
            string parameterString = parameterBuilder.ToString();

            var canonicalizedRequestBuilder = new StringBuilder();
            canonicalizedRequestBuilder.Append( HttpMethod.Post.Method );
            canonicalizedRequestBuilder.Append( "&" );
            canonicalizedRequestBuilder.Append( Uri.EscapeDataString( RequestTokenEndpoint ) );
            canonicalizedRequestBuilder.Append( "&" );
            canonicalizedRequestBuilder.Append( Uri.EscapeDataString( parameterString ) );

            string signature = ComputeSignature( consumerSecret, null, canonicalizedRequestBuilder.ToString() );
            authorizationParts.Add( "oauth_signature", signature );

            var authorizationHeaderBuilder = new StringBuilder();
            authorizationHeaderBuilder.Append( "OAuth " );
            foreach ( var authorizationPart in authorizationParts )
            {
                authorizationHeaderBuilder.AppendFormat(
                    "{0}=\"{1}\", ", authorizationPart.Key, Uri.EscapeDataString( authorizationPart.Value ) );
            }
            authorizationHeaderBuilder.Length = authorizationHeaderBuilder.Length - 2;

            var request = new HttpRequestMessage( HttpMethod.Post, RequestTokenEndpoint );
            request.Headers.Add( "Authorization", authorizationHeaderBuilder.ToString() );

            HttpResponseMessage response = await _httpClient.SendAsync( request, Request.CallCancelled );
            response.EnsureSuccessStatusCode();
            string responseText = await response.Content.ReadAsStringAsync();

            IFormCollection responseParameters = WebHelpers.ParseForm( responseText );
            if ( string.Equals( responseParameters["oauth_callback_confirmed"], "true", StringComparison.InvariantCulture ) )
            {
                return new RequestToken { Token = Uri.UnescapeDataString( responseParameters["oauth_token"] ), TokenSecret = Uri.UnescapeDataString( responseParameters["oauth_token_secret"] ), CallbackConfirmed = true, Properties = properties };
            }

            return new RequestToken();
        }

        private async Task<AccessToken> ObtainAccessTokenAsync( string consumerKey, string consumerSecret, RequestToken token, string verifier )
        {
            _logger.WriteVerbose( "ObtainAccessToken" );

            string nonce = Guid.NewGuid().ToString( "N" );

            var authorizationParts = new SortedDictionary<string, string>
            {
                { "oauth_consumer_key", consumerKey },
                { "oauth_nonce", nonce },
                { "oauth_signature_method", "HMAC-SHA1" },
                { "oauth_token", token.Token },
                { "oauth_timestamp", GenerateTimeStamp() },
                { "oauth_verifier", verifier },
                { "oauth_version", "1.0" },
            };

            var parameterBuilder = new StringBuilder();
            foreach ( var authorizationKey in authorizationParts )
            {
                parameterBuilder.AppendFormat( "{0}={1}&", Uri.EscapeDataString( authorizationKey.Key ), Uri.EscapeDataString( authorizationKey.Value ) );
            }
            parameterBuilder.Length--;
            string parameterString = parameterBuilder.ToString();

            var canonicalizedRequestBuilder = new StringBuilder();
            canonicalizedRequestBuilder.Append( HttpMethod.Post.Method );
            canonicalizedRequestBuilder.Append( "&" );
            canonicalizedRequestBuilder.Append( Uri.EscapeDataString( AccessTokenEndpoint ) );
            canonicalizedRequestBuilder.Append( "&" );
            canonicalizedRequestBuilder.Append( Uri.EscapeDataString( parameterString ) );

            string signature = ComputeSignature( consumerSecret, token.TokenSecret, canonicalizedRequestBuilder.ToString() );
            authorizationParts.Add( "oauth_signature", signature );
            authorizationParts.Remove( "oauth_verifier" );

            var authorizationHeaderBuilder = new StringBuilder();
            authorizationHeaderBuilder.Append( "OAuth " );
            foreach ( var authorizationPart in authorizationParts )
            {
                authorizationHeaderBuilder.AppendFormat(
                    "{0}=\"{1}\", ", authorizationPart.Key, Uri.EscapeDataString( authorizationPart.Value ) );
            }
            authorizationHeaderBuilder.Length = authorizationHeaderBuilder.Length - 2;

            var request = new HttpRequestMessage( HttpMethod.Post, AccessTokenEndpoint );
            request.Headers.Add( "Authorization", authorizationHeaderBuilder.ToString() );

            var formPairs = new List<KeyValuePair<string, string>>()
            {
                new KeyValuePair<string, string>("oauth_verifier", verifier)
            };

            request.Content = new FormUrlEncodedContent( formPairs );

            HttpResponseMessage response = await _httpClient.SendAsync( request, Request.CallCancelled );

            if ( !response.IsSuccessStatusCode )
            {
                _logger.WriteError( "AccessToken request failed with a status code of " + response.StatusCode );
                response.EnsureSuccessStatusCode(); // throw
            }

            string responseText = await response.Content.ReadAsStringAsync();
            IFormCollection responseParameters = WebHelpers.ParseForm( responseText );

            return new AccessToken
            {
                Token = Uri.UnescapeDataString( responseParameters["oauth_token"] ),
                TokenSecret = Uri.UnescapeDataString( responseParameters["oauth_token_secret"] )
            };
        }

        private async Task<JObject> GetUserInformationAsync( string token )
        {
            var response = await _httpClient.GetAsync(
                String.Format( "{0}?key={1}&token={2}", UserInfoEndpoint, Options.Key, token ) );
            response.EnsureSuccessStatusCode();
            return JObject.Parse( await response.Content.ReadAsStringAsync() );
        }

        private static string GenerateTimeStamp()
        {
            TimeSpan secondsSinceUnixEpocStart = DateTime.UtcNow - Epoch;
            return Convert.ToInt64( secondsSinceUnixEpocStart.TotalSeconds ).ToString( CultureInfo.InvariantCulture );
        }

        private static string ComputeSignature( string consumerSecret, string tokenSecret, string signatureData )
        {
            using ( var algorithm = new HMACSHA1() )
            {
                algorithm.Key = Encoding.ASCII.GetBytes(
                    string.Format( CultureInfo.InvariantCulture,
                        "{0}&{1}",
                        Uri.EscapeDataString( consumerSecret ),
                        string.IsNullOrEmpty( tokenSecret ) ? string.Empty : Uri.EscapeDataString( tokenSecret ) ) );
                byte[] hash = algorithm.ComputeHash( Encoding.ASCII.GetBytes( signatureData ) );
                return Convert.ToBase64String( hash );
            }
        }

        private string GetAuthenticationEndpoint( string oauthToken )
        {
            var url = String.Format( "{0}?name={1}&scope={2}&expiration={3}&oauth_token={4}",
                AuthenticationEndpoint,
                Options.ApplicationName,
                Options.Scope.ToScopeString(),
                Options.Expiration.ToExpirationString(),
                oauthToken );
            return url;
        }
    }
}
