using AuthService.AuthModels;
using AuthService.Logic.Workers;

namespace AuthService.Logic.Login
{
    public class Login : ILogin
    {
        private readonly IWorker _worker;
        public Login(IWorker worker)
        {
            _worker = worker;
        }


        public async Task<bool> ActivateCode(string Code)
        {
            var valid = await _worker.ActivateCode(Code);
            return valid;
        }

        public async Task<JwtReponse> LoginUser(LoginUserModel login)
        {
            var userInfo = await _worker.ValidateUserNamePassowrd(login);

            if (userInfo != null)
            {
                /// if account unverified, ask to verify via email
                if (userInfo.AccountStatus == (int)AccountStatusEnum.Unverified)
                    throw new Exception("Account_Error: Please verify your email, we have send you a verification email");

                /// Blocked, no access due security concerns
                if (userInfo.AccountStatus == (int)AccountStatusEnum.Blocked)
                    throw new Exception("Account_Error: There was an issue looking up this account");

                if (userInfo.AccountStatus == (int)AccountStatusEnum.Locked)
                    throw new Exception("Account_Error: This account was locked due to too many bad password attempts");

                JwtReponse token = await _worker.IssueNewToken(login.RememberMe, userInfo);

                _ = await _worker.SaveJwtTokenSignature(token);

                return await Task.FromResult(token);

            }
            else
            {
                throw new Exception("Account_Error: Username or password was invalid!");
            }
        }

        public string RefreshToken(string Token)
        {
            /// validate token issuer  
            if (string.IsNullOrEmpty(Token))
            {
                throw new Exception("invalid user Token");
            }
            return _worker.GenerateRefreshToken(Token);
        }

        public async Task<bool> ValidateUserToken(string Token)
        {
            var ValidAccess = _worker.ValidateTokenExpiration(Token);
            return await Task.FromResult(ValidAccess);
        }

    }
}
