using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace wgvmi15_net_core.Account
{
    public partial class SignOut : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (Request.IsAuthenticated)
            {
                // Redirecionar para a página inicial se o usuário estiver autenticado.
                Response.Redirect("~/");
            }
        }
    }
}