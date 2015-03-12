using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Trello.Messages
{
    public class AccessToken
    {
        public string Token { get; set; }
        public string TokenSecret { get; set; }
    }
}
