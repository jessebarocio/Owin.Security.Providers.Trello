using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Trello.Messages;
using Owin.Security.Providers.Trello.Provider;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;

namespace Owin.Security.Providers.Trello
{
    public class TrelloAuthenticationMiddleware : AuthenticationMiddleware<TrelloAuthenticationOptions>
    {
        private readonly HttpClient httpClient;
        private readonly ILogger logger;

        public TrelloAuthenticationMiddleware( OwinMiddleware next, IAppBuilder app, TrelloAuthenticationOptions options )
            : base( next, options )
        {
            if ( String.IsNullOrWhiteSpace( Options.Key ) )
                throw new ArgumentException( "Key cannot be null." );
            if ( String.IsNullOrWhiteSpace( Options.Secret ) )
                throw new ArgumentException( "Secret cannot be null." );

            logger = app.CreateLogger<TrelloAuthenticationMiddleware>();

            if ( Options.Provider == null )
                Options.Provider = new TrelloAuthenticationProvider();

            if ( Options.StateDataFormat == null )
            {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof( TrelloAuthenticationMiddleware ).FullName,
                    Options.AuthenticationType, "v1" );
                Options.StateDataFormat = new SecureDataFormat<RequestToken>(
                    Serializers.RequestToken,
                    dataProtector,
                    TextEncodings.Base64Url );
            }

            if ( String.IsNullOrEmpty( Options.SignInAsAuthenticationType ) )
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            httpClient = new HttpClient( ResolveHttpMessageHandler( Options ) )
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024 * 1024 * 10
            };

        }

        protected override AuthenticationHandler<TrelloAuthenticationOptions> CreateHandler()
        {
            return new TrelloAuthenticationHandler( httpClient, logger );
        }

        private HttpMessageHandler ResolveHttpMessageHandler( TrelloAuthenticationOptions options )
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if ( options.BackchannelCertificateValidator != null )
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if ( webRequestHandler == null )
                {
                    throw new InvalidOperationException( "An ICertificateValidator cannot be specified at the same time as an HttpMessageHandler unless it is a WebRequestHandler." );
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }
    }
}
