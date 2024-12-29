using AuthService.AuthModels;
using AuthService.SQL_Models;
using System.Security.Claims;

namespace AuthService.Logic.Workers
{
    public interface IWorker
    {
        Task<sqlAccountInfo?> ValidateUserNamePassowrd(LoginUserModel login);
        Task<bool> SaveJwtTokenSignature(JwtReponse jwt);
        Task<JwtReponse> IssueNewToken(bool rememberMe, sqlAccountInfo UserInfo);
        Task<bool> ResetUserPassword(ResetModel reset);
        Task<bool> ActivateCode(string code);
        bool ValidateTokenExpiration(string stringToken);
        Task<string> RequestPasswordReset(ResetRequestModel request);
        Task<string> SignUpNewUser(SignUpUserModel newUser);
        string GenerateRefreshToken(string token);
    }
}