using AuthService.AuthModels;
using AuthService.Logic.Login;
using AuthService.Logic.Reset;
using AuthService.Logic.Signup;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]

    public class AuthController : ControllerBase
    {

        private readonly ILogin _login;
        private readonly IReset _reset;
        private readonly ISignup _signup;

        public AuthController(ILogin login, IReset reset, ISignup signup)
        {
            _login = login;
            _reset = reset;
            _signup = signup;
        }

        //////////////// save sample
        /// https://www.pragimtech.com/blog/blazor/rest-api-repository-pattern/

        /// <summary>
        /// Token generation after validating a login
        /// </summary>
        /// <param name="login"></param>
        /// <returns></returns>

        [AllowAnonymous]
        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginUserModel login)
        {
            JwtReponse token = await _login.LoginUser(login);
            return Ok(token);
        }


        /// <summary>
        ///  verify email account or other temp requests
        /// </summary>
        /// <param name="Code"></param>
        /// <returns></returns>
        [HttpPost("Verify/{Code}")]
        [AllowAnonymous]
        /// the code is the first 7 digits of the uid
        public async Task<IActionResult> VerifyCodes(string Code)
        {
            if (string.IsNullOrEmpty(Code)) return BadRequest();

            var activated = await _login.ActivateCode(Code);

            if (activated)
                return Ok("User email was activated");

            /// only required if changed email, OR before signed in for the first time
            return BadRequest("Account already active or not found");
        }



        /// verify account is not blocked
        /// verify old passowrd match
        /// flag the account as un-verified to disable login
        /// send an email with the reset code 
        /// reset password must be request before changing it.. 

        [HttpPost("ResetRequest")]
        public async Task<IActionResult> ResetRequest([FromBody] ResetRequestModel request)
        {
            if (request != null && ModelState.IsValid)
            {
                var tempCode = await _reset.RequestPasswordReset(request);
                return Ok("Password was reset successfully:" + tempCode);
            }

            return BadRequest("Invalid username or password combination");
        }


        [AllowAnonymous]
        [HttpPost("ResetPassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetModel reset)
        {
            if (reset != null && ModelState.IsValid)
            {
                _ = await _reset.ResetUserPassword(reset);
                return Ok("Password reset successfully");
            }
            else
            {
                return BadRequest("Invalid Reset Request.");
            }
        }

        /// <summary>
        /// Sign up, save user info
        /// requires to vierfy email via a guid to their email acct
        /// can have sms verification too (2 way auth)
        /// </summary>
        /// <param name="newUser"></param>
        /// <returns></returns>

        [HttpPost("SignUp")]
        [AllowAnonymous]
        public async Task<IActionResult> SignUp([FromBody] SignUp_Request newUser)
        {
            string userAdded = await _signup.SignUp(newUser);
            return Ok(userAdded);
        }



        /// <summary>
        ///  custom check: if token valid.. 
        /// </summary>
        /// <param name="stringtoken"></param>
        /// <returns></returns>
        [HttpPost("ValidateToken")]
        public async Task<IActionResult> ValidateToken([FromBody] string stringToken)
        {
            var valid = await _login.ValidateUserToken(stringToken);

            if (valid)
                return Ok(valid);

            return Unauthorized();
        }



        /// <summary>
        /// check certain role
        /// </summary>
        /// <returns></returns>
        [HttpGet("[action]")]
        [Authorize(Roles = "Admin,Editor,User")]
        public IActionResult UsersAccess()
        {
            return Ok("Yes you can access! you are an User.");
        }
        [HttpGet("[action]")]
        [Authorize(Roles = "Admin,Editor")]
        public IActionResult EditorsAccess()
        {
            return Ok("Yes you can access! you are an Editor.");
        }
        [HttpGet("[action]")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminsAccess()
        {
            return Ok("Yes you can access! you are an Editor.");
        }

    }
}
