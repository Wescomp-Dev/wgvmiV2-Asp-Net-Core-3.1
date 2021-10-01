<%@ Page Title="Informações do Usuário" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" Async="true" CodeBehind="UserInfo.aspx.cs" Inherits="wgvmi15_net_core.UserInfo" %>

<asp:Content ID="BodyContent" ContentPlaceHolderID="MainContent" runat="server">
    <h2><%: Title %>.</h2>
    <asp:Panel ID="GetToken" runat="server" Visible="false">
        <p>O token para acessar a API do Graph expirou. Clique <asp:LinkButton runat="server" OnClick="Unnamed_Click">aqui</asp:LinkButton> para entrar e obter um novo token de acesso.</p>
    </asp:Panel>
    <asp:Panel ID="ShowData" runat="server">
          <asp:FormView ID="UserData" runat="server" 
        ItemType="Microsoft.Azure.ActiveDirectory.GraphClient.IUser" 
        RenderOuterTable="false" DefaultMode="ReadOnly"
        ViewStateMode="Disabled">
        <ItemTemplate>
            <table class="table table-bordered table-striped">
                <tr>
                    <td>Nome de Exibição</td>
                    <td><%#: Item.DisplayName %></td>
                </tr>
                <tr>
                    <td>Nome</td>
                    <td><%#: Item.GivenName %></td>
                </tr>
                <tr>
                    <td>Sobrenome</td>
                    <td><%#: Item.Surname %></td>
                </tr>
            </table>
        </ItemTemplate>
    </asp:FormView>
    </asp:Panel>
  
</asp:Content>
