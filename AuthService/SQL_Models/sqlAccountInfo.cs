using System.ComponentModel.DataAnnotations;

namespace AuthService.SQL_Models
{
    public class sqlAccountInfo
    {
        [Key]
        public int ID { get; set; }

        [MaxLength(50)]
        public string? FirstName { get; set; }

        [MaxLength(50)]
        public string? LastName { get; set; }

        [MaxLength(100)]
        public string? Email { get; set; }

        [MaxLength(100)]
        public string? BackupEmail { get; set; }

        [MaxLength(10)]
        public string? Phone { get; set; }

        [MaxLength(50)]
        public string? UserID { get; set; }
        public DateTime? DOB { get; set; }

        [MaxLength(50)]
        public string? UserName { get; set; }

        [MaxLength(1000)]
        public string? Password { get; set; }

        public int AccountStatus { get; set; }
        public int AccountType { get; set; }

        public int? VerifyCodeID { get; set; }

        public DateTime? Joined { get; set; }
    }
}
