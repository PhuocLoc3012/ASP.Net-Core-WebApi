namespace JwtAuthASPNetWebAPI.Core.Dtos
{
    public class AuthServiceResponseDto
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; }
        public string? PersonName { get; set; } = string.Empty;
        public string? Email { get; set; } = string.Empty;
        public string? AccessToken { get; set; } = string.Empty;
        public DateTime? AccessTokenExpiration { get; set; }
        public string? RefreshToken { get; set; } = string.Empty;
        public DateTime? RefreshTokenExpiration { get; set; }
    }
}
