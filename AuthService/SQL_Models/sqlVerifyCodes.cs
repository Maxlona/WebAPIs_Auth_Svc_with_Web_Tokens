using System.ComponentModel.DataAnnotations;

namespace AuthService.SQL_Models
{
    public class sqlVerifyCodes
    {
        [Key]
        public int ID { get; set; }

        [MaxLength(50)]
        public string? UserID { get; set; }

        [MaxLength(100)]
        public string? Code { get; set; }

        public int VerifyType { get; set; }
        public DateTime? VerifyDate { get; set; }
        public DateTime CreationDate { get; set; }
    }
}
