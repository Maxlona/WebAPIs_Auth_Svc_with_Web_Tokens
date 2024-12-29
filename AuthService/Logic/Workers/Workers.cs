using AuthService.AuthModels;
using AuthService.SQL_Models;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Net.Sockets;

namespace AuthService.Logic.Workers
{
    public class Worker : IWorker
    {
        private readonly RepositoryContext _dbCntxt;
        private readonly IConfiguration _config;
        public Worker(RepositoryContext appDbContext, IConfiguration config)
        {
            _dbCntxt = appDbContext;
            _config = config;
        }

        /// <summary>
        /// is valid login? (username/password)
        /// </summary>
        /// <param name="login"></param>
        /// <returns></returns>
        public async Task<sqlAccountInfo?> ValidateUserNamePassowrd(LoginUserModel login)
        {
            sqlAccountInfo? user = _dbCntxt?.AccountInfo?.Where(e =>
                    e.Email == login.Email && e.Password == login.Password).FirstOrDefault();

            return await Task.FromResult(user);
        }

        /// <summary>
        /// save jwt upon login
        /// </summary>
        /// <param name="jwt"></param>
        /// <returns></returns>
        public async Task<bool> SaveJwtTokenSignature(JwtReponse jwt)
        {
            if (jwt != null)
            {
                _ = (_dbCntxt?.AccessToken?.Add(new sqlAccessToken()
                {
                    Token = jwt.token,
                    TokenGUID = jwt.identity,
                    DateTokenRequested = DateTime.Now,
                    Revoked = false,
                    KeepAlive = false, /// first time sign up, no remember me allowed
                    UserID = jwt.userID
                }));

                _ = await _dbCntxt.SaveChangesAsync();

                return await Task.FromResult(true);

            }
            return await Task.FromResult(false);
        }


        /// <summary>
        /// issue new token if login was valid
        /// </summary>
        /// <returns></returns>
        /// 

        public async Task<JwtReponse> IssueNewToken(bool rememberMe, sqlAccountInfo UserInfo)
        {
            string? configJwtKeyValue = _config?.GetSection("Jwt:SecretKey").Value;

            DateTime now = DateTime.UtcNow;
            string sec = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(configJwtKeyValue));

            byte[] secret = Convert.FromBase64String(sec);

            /// remember me/// 28 days, sliding token?
            /// re-sign each 20 minutes

            string ExpirationKey = rememberMe ? "Jwt:28DaysInSeconds" : "Jwt:20MinuteInSeconds";

            int? expirationValue = int.Parse(_config?.GetSection(ExpirationKey).Value ?? "1200");

            DateTime expires = DateTime.UtcNow.AddSeconds(expirationValue.Value);

            ////////////// generate new JWT Token

            // if token expired, just get a new one..

            ////// incase token expired, use refresh token to keep user online for 1 sliding more minute
            byte[] randomNumber = new byte[64];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetNonZeroBytes(randomNumber);
            }
            ///// guid used for sliding new token --or revoking a token
            ///// using sliding tokens.. then must disable "validate token expiration"
            string guid = Convert.ToBase64String(randomNumber);

            string role = Enum.Parse(typeof(AccountTypeEnum), UserInfo.AccountType.ToString()).ToString();

            // claims come from db
            ClaimsIdentity claims = new([
                new Claim(ClaimTypes.Name, UserInfo?.UserID),
                new Claim(ClaimTypes.Role, role), // user/admin...
                new Claim(ClaimTypes.Email, UserInfo?.Email),
            ]);

            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Issuer = _config.GetSection("Jwt:Issuer").Value,
                Audience = _config.GetSection("Jwt:Audience").Value,
                Subject = claims,
                IssuedAt = now,
                Expires = expires,
                TokenType = _config.GetSection("Jwt:TokenType").Value,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256)
            };

            JwtSecurityTokenHandler tokenHandler = new();
            SecurityToken sectoken = tokenHandler.CreateToken(tokenDescriptor);
            string stringtoken = tokenHandler.WriteToken(sectoken);

            /// jwt token model
            JwtReponse jwtReponse = new()
            {
                token = stringtoken,
                expires = expires,
                issueDateTime = now,
                identity = guid,
                email = UserInfo.Email,
                userID = UserInfo.UserID,
            };
            return await Task.FromResult(jwtReponse);
        }

        /// old password and email was verified at "ResetRequest" api
        public async Task<bool> ResetUserPassword(ResetModel reset)
        {
            /// reset account password must be first requested
            sqlVerifyCodes? changeRequest = _dbCntxt?.VerifyCodes?.Where(e =>
                e.VerifyDate == null && e.Code == reset.code).FirstOrDefault();

            if (changeRequest != null)
            {
                /// only active users can change password
                sqlAccountInfo? user = _dbCntxt?.AccountInfo?.Where
                  (e => e.UserID == changeRequest.UserID
                        && e.AccountStatus == (int)AccountStatusEnum.Active).FirstOrDefault();

                if (user != null)
                {
                    user.Password = reset.NewPassword;
                    user.AccountStatus = (int)AccountStatusEnum.Active;
                    changeRequest.VerifyDate = DateTime.Parse(DateTime.Now.ToShortDateString());
                    _dbCntxt.ChangeTracker.DetectChanges();
                    _ = _dbCntxt.SaveChanges();
                    return await Task.FromResult(true);
                }
            }

            throw new Exception("Reset password couldn't complete due to invalid request.");
        }


        public async Task<bool> ActivateCode(string code)
        {
            /// only required if changed email, OR before signed in for the first time

            sqlVerifyCodes? verify = _dbCntxt?.VerifyCodes?.Where(e => e.Code == code && e.VerifyDate == null).FirstOrDefault();
            if (verify != null)
            {
                /// get un-verified user with that code
                sqlAccountInfo? user = _dbCntxt?.AccountInfo?.Where(e => e.UserID == verify.UserID
                        && e.AccountStatus == (int)AccountStatusEnum.Unverified).FirstOrDefault();

                if (user != null)
                {
                    user.AccountStatus = (int)AccountStatusEnum.Active;
                    verify.VerifyDate = DateTime.Parse(DateTime.Now.ToShortDateString());
                    verify.VerifyType = (int)AccountStatusEnum.Active;
                    _dbCntxt?.ChangeTracker.DetectChanges();
                    _ = _dbCntxt?.SaveChanges();

                    return await Task.FromResult(true);
                }
            }

            return false;
        }



        public bool ValidateTokenExpiration(string stringToken)
        {
            if (string.IsNullOrEmpty(stringToken))
            {
                throw new ArgumentNullException(nameof(stringToken));
            }

            string? configJwtKeyValue = _config?.GetSection("Jwt:SecretKey").Value;

            string sec = Convert.ToBase64String(Encoding.UTF8.GetBytes(configJwtKeyValue));

            byte[] secret = Convert.FromBase64String(sec);

            JwtSecurityTokenHandler tokenHandler = new();

            TokenValidationParameters tvp = new()
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidIssuer = _config?.GetSection("Jwt:Issuer").Value,
                ValidAudience = _config?.GetSection("Jwt:Audience").Value,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(secret),
                ValidateLifetime = true
            };

            ClaimsPrincipal principal = tokenHandler.ValidateToken(stringToken, tvp, out SecurityToken securityToken);

            if (principal == null)
            {
                throw new InvalidOperationException("Failed to validate token");
            }

            if (principal != null)
            {
                string? userName = principal.Identity?.Name;

                ///check jwt expiration
                JwtSecurityToken jwtSecurityToken = tokenHandler.ReadJwtToken(stringToken);

                string tokenExp = jwtSecurityToken.Claims.First(claim => claim.Type.Equals("exp")).Value;
                long ticks = long.Parse(tokenExp);
                DateTime tokenDate = DateTimeOffset.FromUnixTimeSeconds(ticks).UtcDateTime;
                DateTime now = DateTime.Now.ToUniversalTime();
                bool valid = tokenDate > now;

                /// Revoking a token is done through "blacklisting" an Email account!
                /// get user email
                string userEmail = jwtSecurityToken.Claims.First(claim => claim.Type.Equals("email")).Value;

                return true;
                /// check if an Email is blacklisted? userEmail
            }
            return false;
        }

        /// <summary>
        /// Refresh tokens are generated of an expired token
        /// no need to re-login...if token was valid, but expired.. refresh it
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public string GenerateRefreshToken(string token)
        {
            /// validat token, if valid but expired, get a new token.. using previous expied token, 
            /// no sign in reuqired

            string? configJwtKeyValue = _config?.GetSection("Jwt:SecretKey").Value;
            string sec = Convert.ToBase64String(Encoding.UTF8.GetBytes(configJwtKeyValue));
            byte[] secret = Convert.FromBase64String(sec);

            JwtSecurityTokenHandler tokenHandler = new();

            TokenValidationParameters tvp = new()
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidIssuer = _config?.GetSection("Jwt:Issuer").Value,
                ValidAudience = _config?.GetSection("Jwt:Audience").Value,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(secret),
                ValidateLifetime = false // must to avoid expiration error
            };

            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, tvp, out SecurityToken securityToken);
            JwtSecurityToken jwtSecurityToken = tokenHandler.ReadJwtToken(token);

            // carry on user claims
            ClaimsIdentity claims = new();
            foreach (var claim in jwtSecurityToken.Claims)
                claims.AddClaim(claim);

            /// add custom flag, is_refresh_token = true
            claims.AddClaim(new Claim("RefreshToken", "true"));

            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Issuer = _config.GetSection("Jwt:Issuer").Value,
                Audience = _config.GetSection("Jwt:Audience").Value,
                Subject = claims,
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddSeconds(180), ///180 for 3 min
                TokenType = _config.GetSection("Jwt:TokenType").Value,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256)
            };

            SecurityToken sectoken = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(sectoken);
        }

        public async Task<string> RequestPasswordReset(ResetRequestModel request)
        {
            var user = CheckIfOldPassMatch(request.Email, request.OldPassword);

            if (user != null)
            {
                /// create a request for confirm email ...new users.. must verify email account
                string tempCode = CreateTempCodeToVerifyUserEmail(user.UserID);

                /// update user with verify email account code
                sqlVerifyCodes? verifyCode = _dbCntxt?.VerifyCodes?.Where(e => e.UserID == user.UserID && e.Code == tempCode).FirstOrDefault();

                if (verifyCode != null)
                {
                    user.VerifyCodeID = verifyCode.ID;
                    _dbCntxt?.ChangeTracker.DetectChanges();
                    _ = (_dbCntxt?.SaveChanges());
                }

                return await Task.FromResult<string>(tempCode);

                //// TODO  // Send email with verification code
            }
            else
            {
                throw new Exception("Not_Found: Email address was not found, please try again");
            }
        }

        public async Task<string> SignUpNewUser(SignUpUserModel newUser)
        {
            var userExists = CheckIfUserExists(newUser.Email, newUser.UserName);

            // account doesn't exist.. create new
            if (userExists == null)
            {
                string NewUserID = Guid.NewGuid().ToString().Replace("-", string.Empty);

                /// add new user
                _ = (_dbCntxt?.AccountInfo?.Add(new sqlAccountInfo()
                {
                    FirstName = newUser.FirstName,
                    LastName = newUser.LastName,
                    Email = newUser.Email,
                    Password = newUser.Password,
                    Phone = newUser.Phone,
                    UserName = newUser.UserName,
                    BackupEmail = newUser.BackupEmail,
                    DOB = DateTime.Parse(newUser.DOB.ToShortDateString()),
                    UserID = NewUserID,
                    /// USER
                    AccountType = (int)AccountTypeEnum.User,
                    /// to be verified via email
                    AccountStatus = (int)VerificationCodeTypes.Email,
                    VerifyCodeID = null,
                    Joined = DateTime.Parse(DateTime.Now.ToShortDateString()),
                }));

                _dbCntxt?.ChangeTracker.DetectChanges();
                _ = (_dbCntxt?.SaveChanges());

                /// create a request for confirm email ...new users.. must verify email account
                string tempCode = CreateTempCodeToVerifyUserEmail(NewUserID);
                return tempCode;
                //// TODO  // Send email with verification code
            }
            else
            {
                throw new Exception("Account_Error: UserName or Email already in use, please try again");
            }
        }

        private sqlAccountInfo? CheckIfUserExists(string Email, string UserName)
        {
            var userExists = _dbCntxt?.AccountInfo?
                  .Where(acc => acc.Email.ToLower() == Email.Trim().ToLower() || acc.UserName == UserName.Trim().ToLower()
                ).FirstOrDefault();
            return userExists;
        }


        private sqlAccountInfo? CheckIfOldPassMatch(string Email, string Pass)
        {
            var userExists = _dbCntxt?.AccountInfo?
                  .Where(acc => acc.Email.ToLower() == Email.Trim().ToLower() && acc.Password == Pass.Trim()
                ).FirstOrDefault();
            return userExists;
        }


        ///  verification codes created when new account created, or request came in to change password
        private string CreateTempCodeToVerifyUserEmail(string UserID)
        {
            string tempCode = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 5).ToUpper();

            /// create a new verify code
            _ = (_dbCntxt?.VerifyCodes?.Add(new sqlVerifyCodes()
            {
                Code = tempCode,
                UserID = UserID,
                CreationDate = DateTime.Parse(DateTime.Now.ToShortDateString()),
                VerifyType = (int)VerificationCodeTypes.Email,
                VerifyDate = null
            }));

            // link temp code to user entry
            _dbCntxt?.ChangeTracker.DetectChanges();
            _ = _dbCntxt?.SaveChanges();

            /// update user with verify email account code

            sqlVerifyCodes? verifyCode = _dbCntxt?.VerifyCodes?.Where(e => e.UserID == UserID && e.Code == tempCode).FirstOrDefault();
            sqlAccountInfo? user = _dbCntxt.AccountInfo.Where(e => e.UserID == UserID && e.Email == e.Email).FirstOrDefault();
            if (user != null)
            {
                user.VerifyCodeID = verifyCode.ID;
                _dbCntxt?.ChangeTracker.DetectChanges();
                _ = (_dbCntxt?.SaveChanges());
            }
            else
            {
                throw new Exception("Account_Error: User was not found");
            }

            return tempCode;
        }


    }
}
