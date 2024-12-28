using System.ComponentModel.DataAnnotations;

namespace AuthService.AuthModels
{
    public class ResetModel
    {
        [Required]
        [MaxLength(100)]
        [MinLength(5)]
        public string? NewPassword { get; set; }
        
        [Required]
        [MinLength(5)]
        [MaxLength(100)]
        public string? code { get; set; }

    }

}
