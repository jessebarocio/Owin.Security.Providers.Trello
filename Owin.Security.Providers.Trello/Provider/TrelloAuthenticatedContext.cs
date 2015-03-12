using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace Owin.Security.Providers.Trello.Provider
{
    public class TrelloAuthenticatedContext : BaseContext
    {
        public string Id { get; set; }
        public string Username { get; set; }
        public string AccessToken { get; private set; }
        public string AccessTokenSecret { get; private set; }
        public JObject User { get; private set; }
        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }

        public TrelloAuthenticatedContext( IOwinContext context, JObject user, string accessToken, string accessTokenSecret )
            : base( context )
        {
            User = user;
            Id = TryGetValue( User, "id" );
            Username = TryGetValue( User, "username" );
            AccessToken = accessToken;
            AccessTokenSecret = accessTokenSecret;
        }

        private static string TryGetValue(JObject user, string property)
        {
            JToken value;
            return user.TryGetValue( property, out value ) ? value.ToString() : null;
        }
    }
}
