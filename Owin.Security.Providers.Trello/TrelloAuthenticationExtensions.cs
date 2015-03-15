using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Trello
{
    public static class TrelloAuthenticationExtensions
    {
        public static IAppBuilder UseTrelloAuthentication( this IAppBuilder app, TrelloAuthenticationOptions options )
        {
            if ( app == null )
                throw new ArgumentNullException( "app" );
            if ( options == null )
                throw new ArgumentNullException( "options" );

            app.Use( typeof( TrelloAuthenticationMiddleware ), app, options );
            return app;
        }

        public static IAppBuilder UseTrelloAuthentication( this IAppBuilder app, string key, string secret, string appName )
        {
            return app.UseTrelloAuthentication( new TrelloAuthenticationOptions( key, secret, appName ) );
        }

        public static IAppBuilder UseTrelloAuthentication( this IAppBuilder app, string key, string secret, string appName, 
            Scope scope, Expiration expiration )
        {
            return app.UseTrelloAuthentication( new TrelloAuthenticationOptions( key, secret, appName, scope, expiration ) );
        }
    }
}
