using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;

namespace wgvmi15_net_core
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
