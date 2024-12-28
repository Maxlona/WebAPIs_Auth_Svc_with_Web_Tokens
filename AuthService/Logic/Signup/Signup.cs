using AuthService.AuthModels;
using AuthService.Logic.Workers;
using AuthService.SQL_Models;
using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics.CodeAnalysis;

namespace AuthService.Logic.Signup
{
    public class Signup: ISignup
    {
        public readonly IWorker _worker;
        private readonly IMapper _mapper;

        public Signup(IWorker worker, IMapper mapper)
        {
            _mapper = mapper;
            _worker = worker;
        }

        public async Task<string> SignUp([FromBody] SignUp_Request newUser)
        {
            if (newUser == null || string.IsNullOrEmpty(newUser.Email) && string.IsNullOrEmpty(newUser.Password))
            {
                throw new Exception("Account_Error: invalid user data");
            }
            /// sample use for automap.
            var signUp_db_model = _mapper.Map<SignUpUserModel>(newUser);
            /// return temp code, to validate account.. till email services added
            string UserAdded = await _worker.SignUpNewUser(signUp_db_model);

            /// user was created
            return UserAdded;
        }
    }
}
