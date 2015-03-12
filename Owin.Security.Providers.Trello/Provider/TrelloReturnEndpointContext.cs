using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Owin.Security.Providers.Trello.Provider
{
    public class TrelloReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="ticket">The authentication ticket</param>
        public TrelloReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket )
            : base( context, ticket )
        {
        }
    }
}
