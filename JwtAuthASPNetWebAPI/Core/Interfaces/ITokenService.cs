using JwtAuthASPNetWebAPI.Core.Entities;
using JwtAuthASPNetWebAPI.Core.OtherObjects;
using System.Security.Claims;

namespace JwtAuthASPNetWebAPI.Core.Interfaces
{
    public interface ITokenService
    {
        Task<TokenModel> GenerateToken(ApplicationUser user, IEnumerable<string> roles);
        Task<ClaimsPrincipal> GetPrincipalFromExpiredToken(string accessToken);
        Task<TokenModel> RefreshToken(TokenModel tokenModel);
    }
}
