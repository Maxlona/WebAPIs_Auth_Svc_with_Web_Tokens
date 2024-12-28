namespace AuthService.AuthModels
{
    public class JwtReponse
    {
        public string? token { get; set; }
        public DateTime expires { get; set; }
        public DateTime issueDateTime { get; set; }
        public string? identity { get; set; }
        public string? email { get; set; }
        public string? userID { get; set; }
    }
}
