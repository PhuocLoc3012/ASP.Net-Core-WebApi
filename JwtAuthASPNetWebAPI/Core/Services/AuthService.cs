﻿using Google.Apis.Auth;
using JwtAuthASPNetWebAPI.Core.Dtos;
using JwtAuthASPNetWebAPI.Core.Dtos.ApiResponse;
using JwtAuthASPNetWebAPI.Core.Dtos.Email;
using JwtAuthASPNetWebAPI.Core.Entities;
using JwtAuthASPNetWebAPI.Core.Interfaces;
using JwtAuthASPNetWebAPI.Core.OtherObjects;
using JwtAuthASPNetWebAPI.Utils;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Web;

namespace JwtAuthASPNetWebAPI.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public readonly IConfiguration _configuration;
        public readonly IEmailService _emailService;
        //private readonly TokenProvider _tokenProvider;
        private readonly ITokenService _tokenService;
        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IEmailService emailService, ITokenService tokenService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
            _tokenService = tokenService;
        }


        public async Task<ApiResponse> LoginAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.Username);
            if (user is null)
            {
                return
                new ApiResponse
                {
                    IsSuccess = false,
                    Message = "Invalid Credentials"
                };
            }
            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);
            if (!isPasswordCorrect)
            {
                return
                new ApiResponse
                {
                    IsSuccess = false,
                    Message = "Invalid Credentials"
                };
            }
            //Claim: Là một mẩu thông tin về người dùng hoặc hệ thống được mã hóa trong token.
            //Các claim có thể chứa thông tin như tên người dùng, vai trò, ID, hoặc bất kỳ thông tin nào khác liên quan đến người dùng.
            //Trong JWT, các claim được tổ chức dưới dạng các cặp key-value. Ví dụ, một claim có thể trông như thế này: "Name": "JohnDoe".
            //var authClaims = new List<Claim>
            //{

            //    new Claim(ClaimTypes.Name, user.UserName),
            //    new Claim(ClaimTypes.NameIdentifier,user.UserName),
            //    new Claim("JWTID", Guid.NewGuid().ToString()),
            //    new Claim("Firstname", user.Firstname),
            //    new Claim("Lastname", user.Lastname),


            //};
            //foreach (var userRole in userRoles)
            //{
            //    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            //}
            //var token = GenerateNewJsonWebToken(authClaims);
            var userRoles = await _userManager.GetRolesAsync(user);
            var tokenModel = await _tokenService.GenerateToken(user, userRoles);
            return new ApiResponse()
            {
                IsSuccess = true,
                Message = "Authentication success",
                Data = tokenModel
            };
        }

        public async Task<ApiResponse> MakeAdminAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.Username);
            if (user is null)
            {
                return new ApiResponse { IsSuccess = false, Message = "Invalid Username!" };
            }
            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);
            return new ApiResponse { IsSuccess = true, Message = "User is now an ADMIN" };
        }

        public async Task<ApiResponse> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.Username);
            if (user is null)
            {
                return new ApiResponse { IsSuccess = false, Message = "Invalid Username!" };
            }
            await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);
            return new ApiResponse { IsSuccess = true, Message = "User is now an OWNER" };
        }

        public async Task<ApiResponse> RegisterAsync(RegisterDto registerDto)
        {
            var isExistsUser = await _userManager.FindByNameAsync(registerDto.Username);
            if (isExistsUser != null)
            {
                return
                new ApiResponse
                {
                    IsSuccess = false,
                    Message = "Username is already exits"
                };
            }
            ApplicationUser newUser = new ApplicationUser()
            {
                Firstname = registerDto.Username,
                Lastname = registerDto.Username,
                Email = registerDto.Email,
                UserName = registerDto.Username,
                SecurityStamp = Guid.NewGuid().ToString(),
                // giúp hệ thống xác định xem thông tin xác thực của người dùng có còn hợp lệ hay không
            };
            var createUserResult = await _userManager.CreateAsync(newUser, registerDto.Password);
            if (!createUserResult.Succeeded)
            {
                var errorString = "User creation failed!";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += "#" + error.Description;
                }
                return new ApiResponse
                {
                    IsSuccess = false,
                    Message = errorString
                };
            }
            // Add a default User role to all users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            // Generate email confirmation token
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);

            // Create a confirmation link
            var confirmationLink = $"http://localhost:3000/confirm-email?userId={newUser.Id}&token={Uri.EscapeDataString(token)}";

            // Send confirmation email
            await _emailService.Send(newUser.Email, "Email Confirmation",
                $"Please confirm your email by clicking on the following link: {confirmationLink}");

            return new ApiResponse
            {
                IsSuccess = true,
                Message = "User created successfully. Please check your email to confirm your account."
            };
        }


        public async Task ConfirmEmail(EmailConfirmationRequest confirmationRequest)
        {
            var user = await _userManager.FindByIdAsync(confirmationRequest.userId);
            if (user is null)
            {
                throw new Exception("User not found");
            }
            var rs = await _userManager.ConfirmEmailAsync(user, confirmationRequest.token);
        }

        public async Task<ApiResponse> SeedRoleAsync()
        {
            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
            {
                return new ApiResponse()
                {
                    IsSuccess = true,
                    Message = "Roles seeding is already done",

                };
            }


            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            return new ApiResponse
            {
                IsSuccess = true,
                Message = "Role Seeding done successfully"
            };
        }




        private string GenerateNewJsonWebToken(List<Claim> claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]));
            var tokenOject = new JwtSecurityToken(
                issuer: _configuration["Jwt:ValidIssuer"],
                audience: _configuration["Jwt:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: claims,
                signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );
            string token = new JwtSecurityTokenHandler().WriteToken(tokenOject);
            return token;

        }

        public async Task<ApiResponse> ForgotPassword(ForgotPasswordDto forgotPasswordDto)
        {
            var user = await _userManager.FindByEmailAsync(forgotPasswordDto.Email);
            if (user == null)
            {
                return new ApiResponse
                {
                    IsSuccess = false,
                    Message = "Email is invalid"
                };
            }
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            //var encodedToken = HttpUtility.UrlEncode(token);  // Mã hóa token
            var param = new Dictionary<string, string>
            {
                { "token", token }, //sử dụng token đã mã hóa
                { "email", forgotPasswordDto.Email }
            };
            var callback = QueryHelpers.AddQueryString(forgotPasswordDto.ClientUri!, param);
            await _emailService.Send(forgotPasswordDto.Email, "Reset password", callback);
            return new ApiResponse
            {
                IsSuccess = true,
                Message = "Send reset password successfully!"
            };
        }

        public async Task<ApiResponse> ResetPassword(ResetPasswordDto resetPasswordDto)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordDto.Email!);
            if (user is null)
            {
                return new ApiResponse
                {
                    IsSuccess = false,
                    Message = "Invalid email!"
                };
            }
            var decodedToken = HttpUtility.UrlDecode(resetPasswordDto.Token!);  // Giải mã token
            var rs = await _userManager.ResetPasswordAsync(user, decodedToken, resetPasswordDto.Password!);
            if (!rs.Succeeded)
            {
                var errorMessages = string.Join(", ", rs.Errors.Select(e => e.Description));
                return new ApiResponse
                {
                    IsSuccess = false,
                    Message = errorMessages
                };
            }
            return new ApiResponse
            {
                IsSuccess = true,
                Message = "Successfull!"
            };
        }




        public async Task<ApiResponse> LoginWithGoogleAsync(string googleToken)
        {
            var settings = new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new List<string> { _configuration["Google:ClientId"] }
            };

            GoogleJsonWebSignature.Payload payload;

            try
            {
                // Xác thực token và lấy payload của Google
                payload = await GoogleJsonWebSignature.ValidateAsync(googleToken, settings);
            }
            catch
            {
                return new ApiResponse  
                {
                    IsSuccess = false,
                    Message = "Invalid Google token."
                };
            }

            // Kiểm tra xem người dùng có tồn tại không
            var user = await _userManager.FindByEmailAsync(payload.Email);
            if (user == null)
            {
                // Tạo người dùng mới nếu chưa tồn tại
                user = new ApplicationUser
                {
                    Email = payload.Email,
                    UserName = payload.Email,
                    Firstname = payload.GivenName,
                    Lastname = payload.FamilyName
                };

                var result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    return new ApiResponse
                    {
                        IsSuccess = false,
                        Message = "Failed to create user."
                    };
                }

                // Thêm role mặc định nếu cần
                await _userManager.AddToRoleAsync(user, StaticUserRoles.USER);
            }

            // Tạo danh sách claims cho người dùng
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("Firstname", user.Firstname),
                new Claim("Lastname", user.Lastname),
                new Claim("JWTID", Guid.NewGuid().ToString())
            };

            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Tạo JWT
            var token = GenerateNewJsonWebToken(claims);

            return new ApiResponse
            {
                IsSuccess = true,
                Message = token
            };
        }


    }
}
