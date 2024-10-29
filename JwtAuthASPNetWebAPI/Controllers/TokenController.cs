using JwtAuthASPNetWebAPI.Core.Interfaces;
using JwtAuthASPNetWebAPI.Core.OtherObjects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthASPNetWebAPI.Controllers
{
    [Route("api/token")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly ITokenService _tokenService;
        public TokenController(ITokenService tokenService)
        {
            _tokenService = tokenService;
        }
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh()
        {
            HttpContext.Request.Cookies.TryGetValue("accessToken", out var accessToken);
            HttpContext.Request.Cookies.TryGetValue("refreshToken", out var refreshToken);
            var tokenModel = new TokenModel { AccessToken = accessToken, RefreshToken = refreshToken };
            var newToken =  await _tokenService.RefreshToken(tokenModel);

            _tokenService.SetTokenInsideCookie(newToken, HttpContext);
            return Ok(newToken);
        }
    }
}
