using Microsoft.Owin.Security.DataHandler.Serializer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Trello.Messages
{
    public static class Serializers
    {
        static Serializers()
        {
            RequestToken = new RequestTokenSerializer();
        }

        /// <summary>
        /// Gets or sets a statically-avaliable serializer object. The value for this property will be <see cref="RequestTokenSerializer"/> by default.
        /// </summary>
        public static IDataSerializer<RequestToken> RequestToken { get; set; }
    }
}
