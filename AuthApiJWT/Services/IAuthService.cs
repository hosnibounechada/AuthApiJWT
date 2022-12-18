using AuthApiJWT.Models;
using AuthApiJWT.Models.Requests;

namespace AuthApiJWT.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> GetTokenAsync(TokenModel model);
        Task<string> AddRoleAsync(RoleModel model);
    }
}
