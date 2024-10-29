using JwtAuthASPNetWebAPI.Core.Entities;
using JwtAuthASPNetWebAPI.Core.OtherObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthASPNetWebAPI.Utils
{
    public sealed class TokenProvider
    {
        public IConfiguration _configuration { get; set; }
        private readonly UserManager<ApplicationUser> _userManager;
        public TokenProvider(IConfiguration configuration, UserManager<ApplicationUser> userManager)
        {
            _configuration = configuration;
            _userManager = userManager;
        }

        public async Task<TokenModel> GenerateToken(ApplicationUser user, IEnumerable<string> roles)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var secretKeyBytes = Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]);

            // Kết hợp các claims của người dùng và roles
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("Id", user.Id.ToString()),
                new Claim("TokenId", Guid.NewGuid().ToString())
            };

            // Thêm các role vào claims
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                //claims: đặc trưng của ng dùng
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(1),
                Issuer =_configuration["Jwt:ValidIssuer"],
                Audience = _configuration["Jwt:ValidAudience"],
                //Kí
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secretKeyBytes), SecurityAlgorithms.HmacSha256),

            }; 

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
           var accessToken =  jwtTokenHandler.WriteToken(token);
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

        private string GenerateRefreshToken()
        {
            var random = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);
                return Convert.ToBase64String(random);
            }
        }

        //Hàm này lấy thông tin của token đã hết hạn để cấp lại token mới
        //Phương thức này sẽ xác thực token và trả về một ClaimsPrincipal, đối tượng này chứa các thông tin (claims) về người dùng được mã hóa trong token.
        public ClaimsPrincipal GetPrincipalFromExpiredToken(string accessToken)
        {
            //1. Thiết lập jwtSettings:
            var jwtSettings = _configuration.GetSection("Jwt");
            //2.Cấu hình TokenValidationParameters:
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Secret"])),
                ValidateLifetime = false,//không kiểm tra token hết hạn do ta sẽ lấy thông tin token để cấp mới
                ValidIssuer = jwtSettings["ValidIssuer"],
                ValidAudience = jwtSettings["ValidAudience"]

            };

            //3. Xác thực Token:
            //sử dụng JwtSecurityTokenHandler để xác thực token dựa trên các thông số tokenValidationParameters đã cấu hình
            //nếu hợp lệ nó sẽ trả về một ClaimsPrincipal
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out securityToken);

            //4. kiểm tra tính hợp lệ của token
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken is null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
               //có thể return ApiResponse
            } 
            return principal;
        }
    }
}
