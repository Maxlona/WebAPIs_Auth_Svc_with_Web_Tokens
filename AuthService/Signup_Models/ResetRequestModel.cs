namespace AuthService.AuthModels
{
    public class ResetRequestModel
    {
        public string? OldPassword { get; set; }
        public string? Email { get; set; }

    }
}
