using System.ComponentModel.DataAnnotations;

namespace AuthService.SQL_Models
{
    public class sqlAccessToken
    {
        [Key]
        public int TokenID { get; set; }

        [MaxLength(100)]
        public string? TokenGUID { get; set; }

        [MaxLength(500)]
        public string? Token { get; set; }
        public DateTime DateTokenRequested { get; set; }

        [MaxLength(50)]
        public string? UserID { get; set; }
        public bool Revoked { get; set; }
        ///  remember me?
        public bool KeepAlive { get; set; }
    }
}
