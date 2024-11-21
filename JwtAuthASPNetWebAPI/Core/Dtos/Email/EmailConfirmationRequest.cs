namespace JwtAuthASPNetWebAPI.Core.Dtos.Email
{
    public class EmailConfirmationRequest
    {
        public string userId { get; set; }
        public string token { get; set; }
    }
}
