using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Trello
{
    internal static class ExtensionMethods
    {
        public static string ToScopeString( this Scope scope )
        {
            switch ( scope )
            {
                case Scope.Read:
                    return "read";
                case Scope.Write:
                    return "write";
                case Scope.ReadWrite:
                default:
                    return "read,write";
                case Scope.ReadWriteAccount:
                    return "read,write,account";
            }
        }

        public static string ToExpirationString( this Expiration expiration )
        {
            switch ( expiration )
            {
                case Expiration.OneHour:
                    return "1hour";
                case Expiration.OneDay:
                    return "1day";
                case Expiration.ThirtyDays:
                    return "30days";
                case Expiration.Never:
                default:
                    return "never";
            }
        }
    }
}
