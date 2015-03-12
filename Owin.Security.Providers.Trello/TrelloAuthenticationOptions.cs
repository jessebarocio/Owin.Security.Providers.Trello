using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Providers.Trello.Messages;
using Owin.Security.Providers.Trello.Provider;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;

namespace Owin.Security.Providers.Trello
{
    public class TrelloAuthenticationOptions : AuthenticationOptions
    {
        public string Key { get; set; }
        public string Secret { get; set; }
        public ITrelloAuthenticationProvider Provider { get; set; }
        public ISecureDataFormat<RequestToken> StateDataFormat { get; set; }
        public string SignInAsAuthenticationType { get; set; }

        public ICertificateValidator BackchannelCertificateValidator { get; set; }
        public HttpMessageHandler BackchannelHttpHandler { get; set; }
        public TimeSpan BackchannelTimeout { get; set; }

        public PathString CallbackPath { get; set; }
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        public string ApplicationName { get; set; }
        public Scope Scope { get; set; }
        public Expiration Expiration { get; set; }

        public TrelloAuthenticationOptions( string key, string secret, string applicationName, 
            Scope scope = Scope.ReadWrite, Expiration expiration = Expiration.Never )
            : base( "Trello" )
        {
            // User settings
            Key = key;
            Secret = secret;
            ApplicationName = applicationName;
            Scope = scope;
            Expiration = expiration;
            // Backend settings
            Caption = "Trello";
            CallbackPath = new PathString( "/signin-trello" );
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds( 60 );
        }
    }

    public enum Scope
    {
        Read,
        Write,
        ReadWrite,
        ReadWriteAccount
    }

    public enum Expiration
    {
        OneHour,
        OneDay,
        ThirtyDays,
        Never
    }
}
