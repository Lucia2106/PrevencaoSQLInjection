using PrevencaoSQLInjection.Data;
using PrevencaoSQLInjection.Data.Entities;
using PrevencaoSQLInjection.Repositories.Interfaces;
using System.Data;

namespace PrevencaoSQLInjection.Repositories.Implementations
{
    public class UserRepository : IUserRepository
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<UserRepository> _logger;

        public UserRepository(
            ApplicationDbContext context,
            IConfiguration configuration,
            ILogger<UserRepository> logger)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;
        }

        // Método SEGURO usando Entity Framework (parametrização implícita)
        public async Task<User> GetUserByLoginSafeAsync(string login)
        {
            try
            {
                return await _context.Users
                    .AsNoTracking()
                    .FirstOrDefaultAsync(u => u.Login == login);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao buscar usuário por login (método seguro)");
                throw;
            }
        }

        // Método SEGURO usando ADO.NET com parâmetros
        public async Task<User> GetUserByLoginAdoSafeAsync(string login)
        {
            User user = null;

            var connectionString = _configuration.GetConnectionString("DefaultConnection");

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                // CONSULTA PARAMETRIZADA - Técnica de prevenção
                var sql = "SELECT Id, Login, Email, PasswordHash, Salt, CreatedAt, " +
                         "LastLoginAt, FailedLoginAttempts, IsLocked, LockedUntil " +
                         "FROM Users WHERE Login = @Login";

                using (var command = new SqlCommand(sql, connection))
                {
                    // Adiciona parâmetro de forma segura
                    command.Parameters.Add("@Login", SqlDbType.VarChar, 50).Value = login;

                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            user = new User
                            {
                                Id = reader.GetInt32(0),
                                Login = reader.GetString(1),
                                Email = reader.GetString(2),
                                PasswordHash = reader.GetString(3),
                                Salt = reader.GetString(4),
                                CreatedAt = reader.GetDateTime(5),
                                LastLoginAt = reader.IsDBNull(6) ? null : reader.GetDateTime(6),
                                FailedLoginAttempts = reader.GetInt32(7),
                                IsLocked = reader.GetBoolean(8),
                                LockedUntil = reader.IsDBNull(9) ? null : reader.GetDateTime(9)
                            };
                        }
                    }
                }
            }

            return user;
        }

        // Método VULNERÁVEL - APENAS PARA DEMONSTRAÇÃO
        public async Task<User> GetUserByLoginUnsafeAsync(string login)
        {
            User user = null;

            var connectionString = _configuration.GetConnectionString("DefaultConnection");

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                // CONCATENAÇÃO DIRETA - VULNERÁVEL A SQL INJECTION
                var sql = $"SELECT Id, Login, Email, PasswordHash, Salt, CreatedAt, " +
                         $"LastLoginAt, FailedLoginAttempts, IsLocked, LockedUntil " +
                         $"FROM Users WHERE Login = '{login}'";

                using (var command = new SqlCommand(sql, connection))
                {
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            user = new User
                            {
                                Id = reader.GetInt32(0),
                                Login = reader.GetString(1),
                                Email = reader.GetString(2),
                                PasswordHash = reader.GetString(3),
                                Salt = reader.GetString(4),
                                CreatedAt = reader.GetDateTime(5),
                                LastLoginAt = reader.IsDBNull(6) ? null : reader.GetDateTime(6),
                                FailedLoginAttempts = reader.GetInt32(7),
                                IsLocked = reader.GetBoolean(8),
                                LockedUntil = reader.IsDBNull(9) ? null : reader.GetDateTime(9)
                            };
                        }
                    }
                }
            }

            return user;
        }

        // Método SEGURO usando Stored Procedure
        public async Task<User> GetUserByLoginStoredProcedureAsync(string login)
        {
            User user = null;

            var connectionString = _configuration.GetConnectionString("DefaultConnection");

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                using (var command = new SqlCommand("sp_GetUserByLogin", connection))
                {
                    command.CommandType = CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@Login", login);

                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            user = new User
                            {
                                Id = reader.GetInt32(0),
                                Login = reader.GetString(1),
                                Email = reader.GetString(2),
                                PasswordHash = reader.GetString(3),
                                Salt = reader.GetString(4),
                                CreatedAt = reader.GetDateTime(5),
                                LastLoginAt = reader.IsDBNull(6) ? null : reader.GetDateTime(6),
                                FailedLoginAttempts = reader.GetInt32(7),
                                IsLocked = reader.GetBoolean(8),
                                LockedUntil = reader.IsDBNull(9) ? null : reader.GetDateTime(9)
                            };
                        }
                    }
                }
            }

            return user;
        }

        public async Task<bool> ValidateUserCredentialsAsync(string login, string passwordHash)
        {
            // Validação segura usando parâmetros
            var sql = "SELECT COUNT(1) FROM Users WHERE Login = @Login AND PasswordHash = @PasswordHash";

            var connectionString = _configuration.GetConnectionString("DefaultConnection");

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                using (var command = new SqlCommand(sql, connection))
                {
                    command.Parameters.Add("@Login", SqlDbType.VarChar, 50).Value = login;
                    command.Parameters.Add("@PasswordHash", SqlDbType.VarChar, 255).Value = passwordHash;

                    var result = await command.ExecuteScalarAsync();
                    return Convert.ToInt32(result) > 0;
                }
            }
        }

        public async Task<int> CreateUserAsync(User user)
        {
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return user.Id;
        }

        public async Task UpdateUserAsync(User user)
        {
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
        }

        public async Task<bool> LoginExistsAsync(string login)
        {
            return await _context.Users
                .AsNoTracking()
                .AnyAsync(u => u.Login == login);
        }

        public async Task<bool> EmailExistsAsync(string email)
        {
            return await _context.Users
                .AsNoTracking()
                .AnyAsync(u => u.Email == email);
        }
    }
}
