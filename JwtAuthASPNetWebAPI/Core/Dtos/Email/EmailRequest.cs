namespace JwtAuthASPNetWebAPI.Core.Dtos.Email
{
    public class EmailRequest
    {
        public string To { get; set; }
        public string Subject { get; set; }
        public string Message { get; set; }
    }
}
