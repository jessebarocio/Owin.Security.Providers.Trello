using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Trello.Provider
{
    public class TrelloApplyRedirectContext : BaseContext<TrelloAuthenticationOptions>
    {
        public TrelloApplyRedirectContext( IOwinContext context, TrelloAuthenticationOptions options,
            AuthenticationProperties properties, string redirectUri )
            : base( context, options )
        {
            RedirectUri = redirectUri;
            Properties = properties;
        }

        public string RedirectUri { get; private set; }
        public AuthenticationProperties Properties { get; private set; }
    }
}
