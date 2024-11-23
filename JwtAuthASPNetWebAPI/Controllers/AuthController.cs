using JwtAuthASPNetWebAPI.Core.Dtos;
using JwtAuthASPNetWebAPI.Core.Entities;
using JwtAuthASPNetWebAPI.Core.Interfaces;
using JwtAuthASPNetWebAPI.Core.OtherObjects;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Text;
using JwtAuthASPNetWebAPI.Core.Dtos.GoogleDto;
using JwtAuthASPNetWebAPI.Core.Dtos.Email;

namespace JwtAuthASPNetWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IEmailService _emailService;
        private readonly ITokenService _tokenService;
        private readonly UserManager<ApplicationUser> _userManager;
        public AuthController(IAuthService authService, UserManager<ApplicationUser> userManager,IEmailService emailService, ITokenService tokenService)
        {
            _authService = authService;
            _emailService = emailService;
            _userManager = userManager;
            _tokenService = tokenService;
        }
        //Route for seeding my roles to DB
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seerRoles = await _authService.SeedRoleAsync();
            return Ok(seerRoles);
        }

        //Route  --> Register
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var registerResult = await _authService.RegisterAsync(registerDto);
            if (registerResult.IsSuccess)
            {
                return StatusCode(StatusCodes.Status201Created, registerResult);
            }
            return BadRequest(registerResult);
        }

        [HttpPost("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(EmailConfirmationRequest emailConfirmationRequest)
        {
            await _authService.ConfirmEmail(emailConfirmationRequest);
            return Ok();
        }







        // Route --> Login
        [HttpPost]
        [Route("login")]

        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var loginResult = await _authService.LoginAsync(loginDto);
            if (loginResult.IsSuccess)
            {
                
                _tokenService.SetTokenInsideCookie((TokenModel)loginResult.Data, HttpContext);
                return Ok(loginResult);
            }
            return Unauthorized(loginResult);
        }




        // Route --> make user --> admin
        [HttpPost]
        [Route("make-admin")]
        public async Task<IActionResult> MakeAmin([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var operationResult = await _authService.MakeAdminAsync(updatePermissionDto);
            if (operationResult.IsSuccess)
            {
                return Ok(operationResult);
            }
            return BadRequest(operationResult);
        }

        // Route --> make user --> OWNER
        [HttpPost]
        [Route("make-owner")]
        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var operationResult = await _authService.MakeOwnerAsync(updatePermissionDto);
            if (operationResult.IsSuccess)
            {
                return Ok(operationResult);
            }
            return BadRequest(operationResult);
        }


        [HttpPost("forgotpassword")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto forgotPasswordDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }
            var rs = await _authService.ForgotPassword(forgotPasswordDto);
            
            return Ok(rs);
        }


        [HttpPost("resetpassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto resetPasswordDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var rs =  await _authService.ResetPassword(resetPasswordDto);
            return Ok(rs);
        }

        //[HttpGet("login-google")]
        //public IActionResult LoginWithGoogle()
        //{
        //    var properties = new AuthenticationProperties { RedirectUri = Url.Action("GoogleResponse") };
        //    return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        //}

        [HttpGet("google-response")]
        public async Task<IActionResult> GoogleResponse()
        {
            var result = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);
            if (!result.Succeeded)
                return Unauthorized();

            var claims = result.Principal?.Identities.FirstOrDefault()?.Claims.Select(claim => new
            {
                claim.Type,
                claim.Value
            });

            return Ok(claims); // Trả về các thông tin lấy từ Google
        }


        [HttpPost("login-google")]
        public async Task<IActionResult> LoginWithGoogle([FromBody] GoogleLoginDto googleLoginDto)
        {
            var result = await _authService.LoginWithGoogleAsync(googleLoginDto.GoogleToken);
            if (!result.IsSuccess)
            {
                return Unauthorized(result.Message);
            }
            return Ok(result.Message);
        }


    }

}
//ValidateIssuer = true,
//                        ValidateAudience = true,
//                        ValidIssuer = builder.Configuration["Jwt:ValidIssuer"],
//                        ValidAudience = builder.Configuration["Jwt:ValidAudience"],
//                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Secret"]))