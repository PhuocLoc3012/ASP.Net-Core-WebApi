using JwtAuthASPNetWebAPI.Core.Dtos;

namespace JwtAuthASPNetWebAPI.Core.Interfaces
{
    public interface IAuthService
    {
        Task<AuthServiceResponseDto> SeedRoleAsync();
        Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto);   
        Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto);
        Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto);
        Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto);

        Task<AuthServiceResponseDto> ForgotPassword (ForgotPasswordDto forgotPasswordDto);
        Task<AuthServiceResponseDto> ResetPassword(ResetPasswordDto resetPasswordDto);

        Task<AuthServiceResponseDto> LoginWithGoogleAsync(string googleToken);
    }
}
