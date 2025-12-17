using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PrevencaoSQLInjection.DTOs.Clients;
using PrevencaoSQLInjection.Services;
using System.Security;

namespace PrevencaoSQLInjection.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class ClientsController : ControllerBase
    {
        private readonly IClientService _clientService;
        private readonly ILogger<ClientsController> _logger;

        public ClientsController(
            IClientService clientService,
            ILogger<ClientsController> logger)
        {
            _clientService = clientService;
            _logger = logger;
        }

        [HttpGet("safe/{cpf}")]
        public async Task<ActionResult<ClientResponse>> GetClientSafe(string cpf)
        {
            try
            {
                var client = await _clientService.GetClientByCpfSafeAsync(cpf);

                if (client == null)
                {
                    return NotFound("Cliente não encontrado");
                }

                return Ok(client);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (SecurityException ex)
            {
                _logger.LogWarning("Tentativa de acesso malicioso detectada");
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao buscar cliente (método seguro)");
                return StatusCode(500, "Erro interno do servidor");
            }
        }

        [HttpGet("unsafe/{cpf}")]
        [AllowAnonymous] // Permitir acesso sem autenticação para demonstração
        public async Task<ActionResult<ClientResponse>> GetClientUnsafe(string cpf)
        {
            try
            {
                // MÉTODO VULNERÁVEL - APENAS PARA DEMONSTRAÇÃO
                var client = await _clientService.GetClientByCpfUnsafeAsync(cpf);

                if (client == null)
                {
                    return NotFound("Cliente não encontrado");
                }

                return Ok(client);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao buscar cliente (método vulnerável)");
                return StatusCode(500, "Erro interno do servidor");
            }
        }

        [HttpPost("search-safe")]
        public async Task<ActionResult<IEnumerable<ClientResponse>>> SearchClientsSafe(
            ClientSearchRequest request)
        {
            try
            {
                var clients = await _clientService.SearchClientsSafeAsync(request);
                return Ok(clients);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (SecurityException ex)
            {
                _logger.LogWarning("Tentativa de busca maliciosa detectada");
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro na busca de clientes (método seguro)");
                return StatusCode(500, "Erro interno do servidor");
            }
        }

        [HttpPost("search-unsafe")]
        [AllowAnonymous]
        public async Task<ActionResult<IEnumerable<ClientResponse>>> SearchClientsUnsafe(
            ClientSearchRequest request)
        {
            try
            {
                // MÉTODO VULNERÁVEL - APENAS PARA DEMONSTRAÇÃO
                var clients = await _clientService.SearchClientsUnsafeAsync(request);
                return Ok(clients);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro na busca de clientes (método vulnerável)");
                return StatusCode(500, "Erro interno do servidor");
            }
        }

        [HttpPost]
        public async Task<ActionResult<ClientResponse>> CreateClient(
            ClientCreateRequest request)
        {
            try
            {
                var client = await _clientService.CreateClientAsync(request);
                return CreatedAtAction(
                    nameof(GetClientSafe),
                    new { cpf = client.CPF },
                    client);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (InvalidOperationException ex)
            {
                return Conflict(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao criar cliente");
                return StatusCode(500, "Erro interno do servidor");
            }
        }

        [HttpPut("{id}")]
        public async Task<ActionResult<ClientResponse>> UpdateClient(
            int id, ClientCreateRequest request)
        {
            try
            {
                var client = await _clientService.UpdateClientAsync(id, request);
                return Ok(client);
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(ex.Message);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao atualizar cliente");
                return StatusCode(500, "Erro interno do servidor");
            }
        }

        [HttpDelete("{id}")]
        public async Task<ActionResult> DeleteClient(int id)
        {
            try
            {
                await _clientService.DeleteClientAsync(id);
                return NoContent();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao excluir cliente");
                return StatusCode(500, "Erro interno do servidor");
            }
        }
    }
}
