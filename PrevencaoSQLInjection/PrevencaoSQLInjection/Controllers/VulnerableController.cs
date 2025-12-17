using Microsoft.AspNetCore.Mvc;
using PrevencaoSQLInjection.Data.Entities;

namespace PrevencaoSQLInjection.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<VulnerableController> _logger;

        public VulnerableController(
            IConfiguration configuration,
            ILogger<VulnerableController> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        [HttpGet("login-vulnerable")]
        public async Task<ActionResult> LoginVulnerable(string username, string password)
        {
            // CONTROLLER VULNERÁVEL - APENAS PARA DEMONSTRAÇÃO
            var connectionString = _configuration.GetConnectionString("DefaultConnection");

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                // VULNERABILIDADE CRÍTICA: concatenação direta
                var sql = $"SELECT * FROM Users WHERE Login = '{username}' AND PasswordHash = '{password}'";

                _logger.LogWarning("Executando consulta vulnerável: {Sql}", sql);

                using (var command = new SqlCommand(sql, connection))
                {
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            return Ok(new { Message = "Login bem-sucedido (VULNERÁVEL)" });
                        }
                    }
                }
            }

            return Unauthorized("Credenciais inválidas");
        }

        [HttpGet("clients-vulnerable")]
        public async Task<ActionResult<IEnumerable<Client>>> GetClientsVulnerable(string search)
        {
            // VULNERABILIDADE: SQL Injection em consulta de busca
            var connectionString = _configuration.GetConnectionString("DefaultConnection");
            var clients = new List<Client>();

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                // VULNERABILIDADE: entrada do usuário concatenada diretamente
                var sql = $"SELECT * FROM Clients WHERE Name LIKE '%{search}%' OR CPF LIKE '%{search}%'";

                _logger.LogWarning("Executando consulta vulnerável: {Sql}", sql);

                using (var command = new SqlCommand(sql, connection))
                {
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        while (await reader.ReadAsync())
                        {
                            clients.Add(new Client
                            {
                                Id = reader.GetInt32(0),
                                Name = reader.GetString(1),
                                CPF = reader.GetString(2),
                                Email = reader.IsDBNull(3) ? null : reader.GetString(3),
                                Phone = reader.IsDBNull(4) ? null : reader.GetString(4),
                                CreatedAt = reader.GetDateTime(5),
                                IsActive = reader.GetBoolean(6)
                            });
                        }
                    }
                }
            }

            return Ok(clients);
        }

        [HttpDelete("delete-vulnerable")]
        public async Task<ActionResult> DeleteVulnerable(string id)
        {
            // VULNERABILIDADE CRÍTICA: SQL Injection em operação DELETE
            var connectionString = _configuration.GetConnectionString("DefaultConnection");

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                // VULNERABILIDADE: entrada do usuário usada diretamente
                var sql = $"DELETE FROM Clients WHERE Id = {id}";

                _logger.LogWarning("Executando DELETE vulnerável: {Sql}", sql);

                using (var command = new SqlCommand(sql, connection))
                {
                    var rowsAffected = await command.ExecuteNonQueryAsync();
                    return Ok(new { RowsAffected = rowsAffected });
                }
            }
        }
    }
}
