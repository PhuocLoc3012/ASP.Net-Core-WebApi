using JwtAuthASPNetWebAPI.Core.Entities;
using JwtAuthASPNetWebAPI.Core.OtherObjects;
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
        public TokenProvider(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public TokenModel GenerateToken(ApplicationUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();


            var secretKeyBytes = Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                //claims: đặc trưng của ng dùng
                Subject = new ClaimsIdentity
                (new[]
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim("Id", user.Id.ToString()),
                    new Claim("TokenId", Guid.NewGuid().ToString())
                    //roles
                }),
                Expires = DateTime.UtcNow.AddMinutes(1),
                Issuer =_configuration["Jwt:ValidIssuer"],
                Audience = _configuration["Jwt:ValidAudience"],
                //Kí
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secretKeyBytes), SecurityAlgorithms.HmacSha256),

            }; 

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
           var accessToken =  jwtTokenHandler.WriteToken(token);

            return new TokenModel
            {
                AccessToken = accessToken,
                RefreshToken = GenerateRefreshToken()
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
    }
}
