using PrevencaoSQLInjection.Data.Entities;

namespace PrevencaoSQLInjection.Repositories.Interfaces
{
    public interface IUserRepository
    {
        Task<User> GetUserByLoginSafeAsync(string login);
        Task<User> GetUserByLoginUnsafeAsync(string login);
        Task<bool> ValidateUserCredentialsAsync(string login, string passwordHash);
        Task<int> CreateUserAsync(User user);
        Task UpdateUserAsync(User user);
        Task<bool> LoginExistsAsync(string login);
        Task<bool> EmailExistsAsync(string email);
    }
}
