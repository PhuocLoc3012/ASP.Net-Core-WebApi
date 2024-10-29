using JwtAuthASPNetWebAPI.Core.Dtos;
using JwtAuthASPNetWebAPI.Core.Dtos.ApiResponse;
using JwtAuthASPNetWebAPI.Core.OtherObjects;

namespace JwtAuthASPNetWebAPI.Core.Interfaces
{
    public interface IAuthService
    {
        Task<ApiResponse> SeedRoleAsync();
        Task<ApiResponse> RegisterAsync(RegisterDto registerDto);   
        Task<ApiResponse> LoginAsync(LoginDto loginDto);
        Task<ApiResponse> MakeAdminAsync(UpdatePermissionDto updatePermissionDto);
        Task<ApiResponse> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto);

        Task<ApiResponse> ForgotPassword (ForgotPasswordDto forgotPasswordDto);
        Task<ApiResponse> ResetPassword(ResetPasswordDto resetPasswordDto);

        Task<ApiResponse> LoginWithGoogleAsync(string googleToken);

    }
}
