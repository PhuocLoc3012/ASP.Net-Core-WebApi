using System.ComponentModel.DataAnnotations;

namespace JwtAuthASPNetWebAPI.Core.Dtos
{
    public class ForgotPasswordDto
    {
        [Required] 
        public string Email { get; set; }

        [Required] 
        public string ClientUri { get; set; }
    }
}
