using JwtAuthASPNetWebAPI.Core.Entities;
using JwtAuthASPNetWebAPI.Core.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace JwtAuthASPNetWebAPI.Core.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        public UserService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }
        public async Task DeleteUnconfirmedUserAsync()
        {
            var users = _userManager.Users.Where(u => !u.EmailConfirmed && u.CreatedDate < DateTime.UtcNow.AddDays(-2));
            foreach (var user in users)
            {
                await _userManager.DeleteAsync(user);
            }
        }
    
    }
}
