using AuthService.AuthModels;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Logic.Login
{
    public interface ILogin
    {
        Task<bool> ActivateCode(string Code);

        Task<JwtReponse> LoginUser(LoginUserModel login);

        Task<bool> ValidateUserToken(string Token);
    }
}
