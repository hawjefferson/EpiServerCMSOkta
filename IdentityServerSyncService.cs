namespace EpiserverSite1
{
    using System.Security.Claims;
    using System.Threading.Tasks;

    using EPiServer.Security;

    public class IdentityServerSyncService : SynchronizingUserService
    {
        public override Task SynchronizeAsync(ClaimsIdentity identity)
        {
            // Transform the passed role claims to System.Security.Claims
            foreach (var claim in identity.Claims)
            {
                if (claim.Type == "role")
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, claim.Value));
                }
            }

            return base.SynchronizeAsync(identity);
        }
    }
}