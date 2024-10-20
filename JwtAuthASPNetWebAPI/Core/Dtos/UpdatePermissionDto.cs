using System.ComponentModel.DataAnnotations;

namespace JwtAuthASPNetWebAPI.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "User name is required")]
        public string Username { get; set; }
    }
}
