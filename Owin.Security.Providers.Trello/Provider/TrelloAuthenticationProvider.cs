using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Trello.Provider
{
    public class TrelloAuthenticationProvider : ITrelloAuthenticationProvider
    {
        public TrelloAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>( null );
            OnReturnEndpoint = context => Task.FromResult<object>( null );
            OnApplyRedirect = context =>
                context.Response.Redirect( context.RedirectUri );
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<TrelloAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<TrelloReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public Action<TrelloApplyRedirectContext> OnApplyRedirect { get; set; }

        public Task Authenticated( TrelloAuthenticatedContext context )
        {
            return OnAuthenticated( context );
        }

        public Task ReturnEndpoint( TrelloReturnEndpointContext context )
        {
            return OnReturnEndpoint( context );
        }

        public virtual void ApplyRedirect( TrelloApplyRedirectContext context )
        {
            OnApplyRedirect( context );
        }
    }
}
