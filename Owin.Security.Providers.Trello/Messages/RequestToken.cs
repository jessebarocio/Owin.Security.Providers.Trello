using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Trello.Messages
{
    public class RequestToken
    {
        public string Token { get; set; }
        public string TokenSecret { get; set; }
        public bool CallbackConfirmed { get; set; }

        public AuthenticationProperties Properties { get; set; }
    }
}
