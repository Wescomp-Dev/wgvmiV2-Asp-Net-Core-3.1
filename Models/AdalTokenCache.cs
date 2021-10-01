using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data.Entity;
using System.Linq;
using System.Web;
using System.Web.Security;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace wgvmi15_net_core.Models
{
    public class ADALTokenCache : TokenCache
    {
        private ApplicationDbContext db = new ApplicationDbContext();
        private string userId;
        private UserTokenCache Cache;

        public ADALTokenCache(string signedInUserId)
        {
            // associar o cache ao usuário atual do aplicativo Web
            userId = signedInUserId;
            this.AfterAccess = AfterAccessNotification;
            this.BeforeAccess = BeforeAccessNotification;
            this.BeforeWrite = BeforeWriteNotification;
            // pesquisar a entrada no banco de dados
            Cache = db.UserTokenCacheList.FirstOrDefault(c => c.webUserUniqueId == userId);
            // colocar a entrada na memória
            this.Deserialize((Cache == null) ? null : MachineKey.Unprotect(Cache.cacheBits,"ADALCache"));
        }

        // limpar o banco de dados
        public override void Clear()
        {
            base.Clear();
            var cacheEntry = db.UserTokenCacheList.FirstOrDefault(c => c.webUserUniqueId == userId);
            db.UserTokenCacheList.Remove(cacheEntry);
            db.SaveChanges();
        }

        // Notificação criada antes do ADAL acessar o cache.
        // Esta é a sua chance de atualizar a cópia na memória do BD, se a versão na memória for obsoleta
        void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            if (Cache == null)
            {
                // primeiro acesso
                Cache = db.UserTokenCacheList.FirstOrDefault(c => c.webUserUniqueId == userId);
            }
            else
            { 
                // recuperar última gravação do BD
                var status = from e in db.UserTokenCacheList
                             where (e.webUserUniqueId == userId)
                select new
                {
                    LastWrite = e.LastWrite
                };

                // se a cópia na memória for anterior à cópia persistente
                if (status.First().LastWrite > Cache.LastWrite)
                {
                    // ler a partir da memória, atualizar cópia na memória
                    Cache = db.UserTokenCacheList.FirstOrDefault(c => c.webUserUniqueId == userId);
                }
            }
            this.Deserialize((Cache == null) ? null : MachineKey.Unprotect(Cache.cacheBits, "ADALCache"));
        }

        // Notificação criada depois do ADAL acessar o cache.
        // Se o sinalizador HasStateChanged estiver definido, ADAL alterou o conteúdo do cache
        void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // se o estado for alterado
            if (this.HasStateChanged)
            {
                if (Cache == null)
                {
                    Cache = new UserTokenCache
                    {
                        webUserUniqueId = userId
                    };
                }

                Cache.cacheBits = MachineKey.Protect(this.Serialize(), "ADALCache");
                Cache.LastWrite = DateTime.Now;

                // atualizar o BD e a última gravação
                db.Entry(Cache).State = Cache.UserTokenCacheId == 0 ? EntityState.Added : EntityState.Modified;
                db.SaveChanges();
                this.HasStateChanged = false;
            }
        }

        void BeforeWriteNotification(TokenCacheNotificationArgs args)
        {
            // se você quiser garantir que nenhuma gravação em simultâneo ocorra, utilize esta notificação para colocar um bloqueio na entrada
        }

        public override void DeleteItem(TokenCacheItem item)
        {
            base.DeleteItem(item);
        }
    }
}
