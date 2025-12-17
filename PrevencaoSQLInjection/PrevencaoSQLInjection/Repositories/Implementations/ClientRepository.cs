using PrevencaoSQLInjection.Data;
using PrevencaoSQLInjection.Data.Entities;
using PrevencaoSQLInjection.Repositories.Interfaces;
using PrevencaoSQLInjection.Services.Security;
using System.Data;
using System.Security;

namespace PrevencaoSQLInjection.Repositories.Implementations
{
    public class ClientRepository : IClientRepository
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<ClientRepository> _logger;
        private readonly IInputValidator _inputValidator;
        private readonly ISqlInjectionDetector _sqlInjectionDetector;

        public ClientRepository(
            ApplicationDbContext context,
            IConfiguration configuration,
            ILogger<ClientRepository> logger,
            IInputValidator inputValidator,
            ISqlInjectionDetector sqlInjectionDetector)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;
            _inputValidator = inputValidator;
            _sqlInjectionDetector = sqlInjectionDetector;
        }

        // Método SEGURO 1: Entity Framework Core
        public async Task<Client> GetClientByCpfSafeAsync(string cpf)
        {
            // Validação de input antes da consulta
            if (!_inputValidator.ValidateCpf(cpf))
            {
                throw new ArgumentException("CPF inválido", nameof(cpf));
            }

            // Detecção de SQL Injection
            if (_sqlInjectionDetector.ContainsSqlInjection(cpf))
            {
                _logger.LogWarning("Tentativa de SQL Injection detectada no CPF: {Cpf}", cpf);
                throw new SecurityException("Entrada maliciosa detectada");
            }

            return await _context.Clients
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.CPF == cpf);
        }

        // Método SEGURO 2: ADO.NET com parâmetros
        public async Task<Client> GetClientByCpfAdoSafeAsync(string cpf)
        {
            // Sanitização do input
            var sanitizedCpf = _inputValidator.SanitizeInput(cpf);

            if (!_inputValidator.ValidateCpf(sanitizedCpf))
            {
                throw new ArgumentException("CPF inválido após sanitização", nameof(cpf));
            }

            Client client = null;
            var connectionString = _configuration.GetConnectionString("DefaultConnection");

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                // CONSULTA PARAMETRIZADA
                var sql = @"SELECT Id, Name, CPF, Email, Phone, CreatedAt, IsActive 
                          FROM Clients 
                          WHERE CPF = @Cpf";

                using (var command = new SqlCommand(sql, connection))
                {
                    // Adiciona parâmetro com tipo específico
                    command.Parameters.Add("@Cpf", SqlDbType.VarChar, 14).Value = sanitizedCpf;

                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            client = MapClientFromReader(reader);
                        }
                    }
                }
            }

            return client;
        }

        // Método SEGURO 3: Stored Procedure
        public async Task<Client> GetClientByCpfStoredProcedureAsync(string cpf)
        {
            if (!_inputValidator.ValidateCpf(cpf))
            {
                throw new ArgumentException("CPF inválido", nameof(cpf));
            }

            Client client = null;
            var connectionString = _configuration.GetConnectionString("DefaultConnection");

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                using (var command = new SqlCommand("sp_GetClientByCpf", connection))
                {
                    command.CommandType = CommandType.StoredProcedure;
                    command.Parameters.AddWithValue("@Cpf", cpf);

                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            client = MapClientFromReader(reader);
                        }
                    }
                }
            }

            return client;
        }

        // Método VULNERÁVEL - APENAS PARA DEMONSTRAÇÃO
        public async Task<Client> GetClientByCpfUnsafeAsync(string cpf)
        {
            Client client = null;
            var connectionString = _configuration.GetConnectionString("DefaultConnection");

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                // CONCATENAÇÃO DIRETA - VULNERÁVEL
                var sql = $"SELECT Id, Name, CPF, Email, Phone, CreatedAt, IsActive " +
                         $"FROM Clients WHERE CPF = '{cpf}'";

                using (var command = new SqlCommand(sql, connection))
                {
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            client = MapClientFromReader(reader);
                        }
                    }
                }
            }

            return client;
        }

        // Busca segura com múltiplos parâmetros
        public async Task<IEnumerable<Client>> SearchClientsSafeAsync(string name, string cpf, string email)
        {
            var connectionString = _configuration.GetConnectionString("DefaultConnection");
            var clients = new List<Client>();

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                // Consulta parametrizada com condições dinâmicas
                var sql = @"SELECT Id, Name, CPF, Email, Phone, CreatedAt, IsActive 
                          FROM Clients 
                          WHERE 1 = 1";

                // Construção dinâmica segura
                var parameters = new List<SqlParameter>();

                if (!string.IsNullOrWhiteSpace(name))
                {
                    sql += " AND Name LIKE @Name";
                    parameters.Add(new SqlParameter("@Name", SqlDbType.VarChar, 100)
                    {
                        Value = $"%{_inputValidator.SanitizeInput(name)}%"
                    });
                }

                if (!string.IsNullOrWhiteSpace(cpf) && _inputValidator.ValidateCpf(cpf))
                {
                    sql += " AND CPF = @Cpf";
                    parameters.Add(new SqlParameter("@Cpf", SqlDbType.VarChar, 14)
                    {
                        Value = cpf
                    });
                }

                if (!string.IsNullOrWhiteSpace(email) && _inputValidator.ValidateEmail(email))
                {
                    sql += " AND Email = @Email";
                    parameters.Add(new SqlParameter("@Email", SqlDbType.VarChar, 100)
                    {
                        Value = email
                    });
                }

                sql += " ORDER BY Name";

                using (var command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddRange(parameters.ToArray());

                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        while (await reader.ReadAsync())
                        {
                            clients.Add(MapClientFromReader(reader));
                        }
                    }
                }
            }

            return clients;
        }

        // Busca vulnerável - APENAS PARA DEMONSTRAÇÃO
        public async Task<IEnumerable<Client>> SearchClientsUnsafeAsync(string name, string cpf, string email)
        {
            var connectionString = _configuration.GetConnectionString("DefaultConnection");
            var clients = new List<Client>();

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                // CONSTRUÇÃO VULNERÁVEL COM CONCATENAÇÃO
                var sql = "SELECT Id, Name, CPF, Email, Phone, CreatedAt, IsActive FROM Clients WHERE 1 = 1";

                if (!string.IsNullOrWhiteSpace(name))
                {
                    sql += $" AND Name LIKE '%{name}%'";
                }

                if (!string.IsNullOrWhiteSpace(cpf))
                {
                    sql += $" AND CPF = '{cpf}'";
                }

                if (!string.IsNullOrWhiteSpace(email))
                {
                    sql += $" AND Email = '{email}'";
                }

                sql += " ORDER BY Name";

                using (var command = new SqlCommand(sql, connection))
                {
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        while (await reader.ReadAsync())
                        {
                            clients.Add(MapClientFromReader(reader));
                        }
                    }
                }
            }

            return clients;
        }

        private Client MapClientFromReader(SqlDataReader reader)
        {
            return new Client
            {
                Id = reader.GetInt32(0),
                Name = reader.GetString(1),
                CPF = reader.GetString(2),
                Email = reader.IsDBNull(3) ? null : reader.GetString(3),
                Phone = reader.IsDBNull(4) ? null : reader.GetString(4),
                CreatedAt = reader.GetDateTime(5),
                IsActive = reader.GetBoolean(6)
            };
        }

        public async Task<int> CreateClientAsync(Client client)
        {
            _context.Clients.Add(client);
            await _context.SaveChangesAsync();
            return client.Id;
        }

        public async Task UpdateClientAsync(Client client)
        {
            _context.Clients.Update(client);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteClientAsync(int id)
        {
            // Deleção segura usando Entity Framework
            var client = await _context.Clients.FindAsync(id);
            if (client != null)
            {
                _context.Clients.Remove(client);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<bool> ClientExistsByCpfAsync(string cpf)
        {
            return await _context.Clients
                .AsNoTracking()
                .AnyAsync(c => c.CPF == cpf);
        }

        public async Task<bool> ClientExistsByEmailAsync(string email)
        {
            return await _context.Clients
                .AsNoTracking()
                .AnyAsync(c => c.Email == email);
        }
    }
}
