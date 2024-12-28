using AuthService.AuthModels;
using AutoMapper;

namespace AuthService.Extensions
{
    public class MapperProfile : Profile
    {
        public MapperProfile()
        {
            CreateMap<SignUp_Request, SignUpUserModel>();
        }
    }
}
