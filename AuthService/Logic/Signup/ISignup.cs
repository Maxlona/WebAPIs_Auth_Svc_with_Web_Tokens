using AuthService.AuthModels;

namespace AuthService.Logic.Signup
{
    public interface ISignup
    {
        Task<string> SignUp(SignUp_Request newUser);
    }
}
