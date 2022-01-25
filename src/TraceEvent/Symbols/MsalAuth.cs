using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

using Microsoft.Identity.Client;

namespace Microsoft.Diagnostics.Symbols
{
#if !NETSTANDARD1_6
    /// <summary>
    /// Signs-in the user to AAD and obtains a token for use with ADO
    /// </summary>
    public static class Msal
    {
        public static readonly string TokenCacheFilePath =
            $"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\\{System.Reflection.Assembly.GetExecutingAssembly().Location}.MsalTokenCache.bin";

        private static readonly object FileLock = new object();

        public static string AcquireToken()
        {
            // The client ID that identifies the client app.
            var clientId = "872cd9fa-d31f-45e0-9eab-6e460a02d1f1";

            // The tenant to sign-in the user to (could also be the tenant ID, a GUID).
            var tenant = "microsoft.com";

            // The sign-in URI for the tenant (here, microsoft.com) is derived from the tenant.
            var authority = $"https://login.microsoftonline.com/{tenant}/v2.0";

            // The authetnication scope -- this GUID is for ADO.
            string[] scopes = new string[] { "499b84ac-1321-427f-aa17-267ca6975798/user_impersonation" };

            // MSAL public client application (so that app has no secrets of its own,
            // only the user is being authenticated)
            var application = PublicClientApplicationBuilder.Create(clientId)
                .WithAuthority(authority)
                .WithDefaultRedirectUri()
                .WithLegacyCacheCompatibility(false)
                .Build();

            // Configure the token cache
            var tokenCache = application.UserTokenCache;
            tokenCache.SetBeforeAccess(BeforeAccessNotification);
            tokenCache.SetAfterAccess(AfterAccessNotification);

            AuthenticationResult result;
            var accounts = application.GetAccountsAsync().Result;
            try
            {
                result = application.AcquireTokenSilent(scopes, accounts.FirstOrDefault()).ExecuteAsync().Result;
            }
            catch (MsalUiRequiredException ex)
            {
                // Token doesn't exist in the cache, or has expired.
                // Prompt the user with a login prompt.
                result = application.AcquireTokenInteractive(scopes)
                    .WithClaims(ex.Claims)
                    .ExecuteAsync().Result;
            }

            return result.AccessToken;
        }

        private static void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            lock (FileLock)
            {
                args
                    .TokenCache
                    .DeserializeMsalV3(
                        File.Exists(TokenCacheFilePath)
                        ? ProtectedData.Unprotect(File.ReadAllBytes(TokenCacheFilePath), null, DataProtectionScope.CurrentUser)
                        : null);
            }
        }

        private static void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // If the access operation resulted in a cache update
            if (args.HasStateChanged)
            {
                lock (FileLock)
                {
                    // reflect changesgs in the persistent store
                    File.WriteAllBytes(TokenCacheFilePath, ProtectedData.Protect(args.TokenCache.SerializeMsalV3(), null, DataProtectionScope.CurrentUser));
                }
            }
        }
    }
#endif
}