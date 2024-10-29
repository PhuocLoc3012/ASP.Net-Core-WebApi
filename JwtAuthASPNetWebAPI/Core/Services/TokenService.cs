using JwtAuthASPNetWebAPI.Core.Entities;
using JwtAuthASPNetWebAPI.Core.Interfaces;
using JwtAuthASPNetWebAPI.Core.OtherObjects;
using JwtAuthASPNetWebAPI.Utils;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthASPNetWebAPI.Core.Services
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        public TokenService(IConfiguration configuration, UserManager<ApplicationUser> userManager)
        {
            _configuration = configuration;
            _userManager = userManager;
        }

        //Tạo accessToken và refresh token
        public async Task<TokenModel> GenerateToken(ApplicationUser user, IEnumerable<string> roles)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var secretKeyBytes = Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]);

            // Kết hợp các claims của người dùng và roles
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("TokenId", Guid.NewGuid().ToString())
            };

            // Thêm các role vào claims
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                //claims: đặc trưng của ng dùng
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(1),
                Issuer = _configuration["Jwt:ValidIssuer"],
                Audience = _configuration["Jwt:ValidAudience"],
                //Kí
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secretKeyBytes), SecurityAlgorithms.HmacSha256),

            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var accessToken = jwtTokenHandler.WriteToken(token);
            var refreshToken = GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiration = DateTime.UtcNow.AddDays(7);
            await _userManager.UpdateAsync(user);
            return new TokenModel
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
            };
        }

        public async Task<ClaimsPrincipal> GetPrincipalFromExpiredToken(string accessToken)
        {
            //Hàm này lấy thông tin của token đã hết hạn để cấp lại token mới
            //Phương thức này sẽ xác thực token và trả về một ClaimsPrincipal, đối tượng này chứa các thông tin (claims) về người dùng được mã hóa trong token.

            //1.Cấu hình TokenValidationParameters:
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"])),
                ValidateLifetime = false,//không kiểm tra token hết hạn do ta sẽ lấy thông tin token để cấp mới
                ValidIssuer = _configuration["Jwt:ValidIssuer"],
                ValidAudience = _configuration["Jwt:ValidAudience"]

            };

            //2. Xác thực Token:
            //sử dụng JwtSecurityTokenHandler để xác thực token dựa trên các thông số tokenValidationParameters đã cấu hình
            //nếu hợp lệ nó sẽ trả về một ClaimsPrincipal
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal =  tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out securityToken);

            //3. kiểm tra tính hợp lệ của token
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken is null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
                //có thể return ApiResponse
            }
            return principal;
        }
        private string GenerateRefreshToken()
        {
            var random = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);
                return Convert.ToBase64String(random);
            }
        }

        public async Task<TokenModel> RefreshToken(TokenModel tokenModel)
        {
            var principal = await GetPrincipalFromExpiredToken(tokenModel.AccessToken);
            Console.WriteLine("==========================================================");
            foreach (var claim in principal.Claims)
            {
                Console.WriteLine($"Claim Type: {claim.Type}, Claim Value: {claim.Value}");
            }
            Console.WriteLine("==========================================================");
            var userNameClaim = principal.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Name);
            var user = await _userManager.FindByNameAsync(userNameClaim?.Value);
            if (user is null || user.RefreshToken != tokenModel.RefreshToken || user.RefreshTokenExpiration <= DateTime.UtcNow)
            {
                throw new Exception();
                //return new ApiResponse
                //{
                //    IsSuccess = false,
                //    Message = "Refresh token failed"
                //};
            }
            var roles = principal.FindAll(ClaimTypes.Role).Select(claim => claim.Value).ToList();
            var rs = await GenerateToken(user, roles);

            //// Cập nhật refresh token
            //user.RefreshToken = rs.RefreshToken;
            ////user.RefreshTokenExpiration =;
            //await _userManager.UpdateAsync(user);

            return rs;

        }

        public void SetTokenInsideCookie(TokenModel tokenModel, HttpContext context)
        {
            context.Response.Cookies.Append("accessToken", tokenModel.AccessToken);
            new CookieOptions
            {
                Expires = DateTime.UtcNow.AddMinutes(5),
                HttpOnly = true,
                IsEssential = true,
                Secure = true,
                SameSite = SameSiteMode.None,
            };
            context.Response.Cookies.Append("refreshToken", tokenModel.RefreshToken);
            new CookieOptions
            {
                Expires = DateTime.UtcNow.AddDays(7),
                HttpOnly = true,
                IsEssential = true,
                Secure = true,
                SameSite = SameSiteMode.None,
            };

        }

    }
}
