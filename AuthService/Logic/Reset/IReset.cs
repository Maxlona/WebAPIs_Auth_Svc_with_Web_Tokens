using AuthService.AuthModels;

namespace AuthService.Logic.Reset
{
    public interface IReset
    {
        Task<bool> ResetUserPassword(ResetModel reset);

        Task<string> RequestPasswordReset(ResetRequestModel request);
    }
}
