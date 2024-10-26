using Microsoft.AspNetCore.Identity;

namespace JwtAuthASPNetWebAPI.Core.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string Firstname { get; set; }
        public string Lastname { get; set; }
    }
}
