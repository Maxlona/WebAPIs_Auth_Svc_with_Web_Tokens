using System.ComponentModel.DataAnnotations;

namespace AuthService.AuthModels
{
    public class LoginUserModel
    {
        [Required]
        [EmailAddress]
        public string? Email { get; set; }

        [Required]
        [MaxLength(100)]
        [MinLength(5)]
        public string? Password { get; set; }

        // sliding 28 days, vs 20 minutes
        public bool RememberMe { get; set; }

    }
}
