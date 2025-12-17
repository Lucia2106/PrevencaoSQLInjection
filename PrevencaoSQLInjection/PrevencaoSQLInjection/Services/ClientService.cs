using PrevencaoSQLInjection.Data.Entities;
using PrevencaoSQLInjection.DTOs.Clients;
using PrevencaoSQLInjection.Repositories.Interfaces;
using PrevencaoSQLInjection.Services.Security;
using System.Security;

namespace PrevencaoSQLInjection.Services
{
    public class ClientService : IClientService
    {
        private readonly IClientRepository _clientRepository;
        private readonly IInputValidator _inputValidator;
        private readonly ISqlInjectionDetector _sqlInjectionDetector;
        private readonly ILogger<ClientService> _logger;

        public ClientService(
            IClientRepository clientRepository,
            IInputValidator inputValidator,
            ISqlInjectionDetector sqlInjectionDetector,
            ILogger<ClientService> logger)
        {
            _clientRepository = clientRepository;
            _inputValidator = inputValidator;
            _sqlInjectionDetector = sqlInjectionDetector;
            _logger = logger;
        }

        public async Task<ClientResponse> GetClientByCpfSafeAsync(string cpf)
        {
            try
            {
                // Validação rigorosa do input
                if (!_inputValidator.ValidateCpf(cpf))
                {
                    throw new ArgumentException("Formato de CPF inválido");
                }

                // Detecção de SQL Injection
                if (_sqlInjectionDetector.ContainsSqlInjection(cpf))
                {
                    _logger.LogWarning("Tentativa de SQL Injection detectada: {Cpf}", cpf);
                    throw new SecurityException("Entrada maliciosa detectada");
                }

                var client = await _clientRepository.GetClientByCpfSafeAsync(cpf);

                if (client == null)
                {
                    return null;
                }

                return MapToClientResponse(client);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao buscar cliente por CPF (método seguro)");
                throw;
            }
        }

        public async Task<ClientResponse> GetClientByCpfUnsafeAsync(string cpf)
        {
            try
            {
                // Método vulnerável - sem validação adequada
                var client = await _clientRepository.GetClientByCpfUnsafeAsync(cpf);

                if (client == null)
                {
                    return null;
                }

                return MapToClientResponse(client);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao buscar cliente por CPF (método vulnerável)");
                throw;
            }
        }

        public async Task<IEnumerable<ClientResponse>> SearchClientsSafeAsync(ClientSearchRequest request)
        {
            try
            {
                // Validação de todos os inputs
                if (!string.IsNullOrWhiteSpace(request.CPF) &&
                    !_inputValidator.ValidateCpf(request.CPF))
                {
                    throw new ArgumentException("CPF inválido");
                }

                if (!string.IsNullOrWhiteSpace(request.Email) &&
                    !_inputValidator.ValidateEmail(request.Email))
                {
                    throw new ArgumentException("Email inválido");
                }

                if (!string.IsNullOrWhiteSpace(request.Name) &&
                    !_inputValidator.ValidateName(request.Name))
                {
                    throw new ArgumentException("Nome inválido");
                }

                // Detecção de SQL Injection em todos os campos
                var allInputs = $"{request.Name} {request.CPF} {request.Email}";
                if (_sqlInjectionDetector.ContainsSqlInjection(allInputs))
                {
                    _logger.LogWarning("Tentativa de SQL Injection detectada na busca");
                    throw new SecurityException("Entrada maliciosa detectada");
                }

                var clients = await _clientRepository.SearchClientsSafeAsync(
                    request.Name, request.CPF, request.Email);

                return clients.Select(MapToClientResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao buscar clientes (método seguro)");
                throw;
            }
        }

        public async Task<IEnumerable<ClientResponse>> SearchClientsUnsafeAsync(ClientSearchRequest request)
        {
            try
            {
                // Método vulnerável - sem validação
                var clients = await _clientRepository.SearchClientsUnsafeAsync(
                    request.Name, request.CPF, request.Email);

                return clients.Select(MapToClientResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao buscar clientes (método vulnerável)");
                throw;
            }
        }

        public async Task<ClientResponse> CreateClientAsync(ClientCreateRequest request)
        {
            try
            {
                // Validação rigorosa de todos os campos
                if (!_inputValidator.ValidateName(request.Name))
                {
                    throw new ArgumentException("Nome inválido");
                }

                if (!_inputValidator.ValidateCpf(request.CPF))
                {
                    throw new ArgumentException("CPF inválido");
                }

                if (!string.IsNullOrWhiteSpace(request.Email) &&
                    !_inputValidator.ValidateEmail(request.Email))
                {
                    throw new ArgumentException("Email inválido");
                }

                if (!string.IsNullOrWhiteSpace(request.Phone) &&
                    !_inputValidator.ValidatePhone(request.Phone))
                {
                    throw new ArgumentException("Telefone inválido");
                }

                // Verificar se CPF já existe
                if (await _clientRepository.ClientExistsByCpfAsync(request.CPF))
                {
                    throw new InvalidOperationException("CPF já cadastrado");
                }

                // Verificar se Email já existe
                if (!string.IsNullOrWhiteSpace(request.Email) &&
                    await _clientRepository.ClientExistsByEmailAsync(request.Email))
                {
                    throw new InvalidOperationException("Email já cadastrado");
                }

                var client = new Client
                {
                    Name = request.Name,
                    CPF = request.CPF,
                    Email = request.Email,
                    Phone = request.Phone,
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                };

                var id = await _clientRepository.CreateClientAsync(client);
                client.Id = id;

                return MapToClientResponse(client);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao criar cliente");
                throw;
            }
        }

        public async Task<ClientResponse> UpdateClientAsync(int id, ClientCreateRequest request)
        {
            try
            {
                // Validações similares ao create
                if (!_inputValidator.ValidateName(request.Name))
                {
                    throw new ArgumentException("Nome inválido");
                }

                if (!_inputValidator.ValidateCpf(request.CPF))
                {
                    throw new ArgumentException("CPF inválido");
                }

                // Buscar cliente existente
                var client = await _clientRepository.GetClientByCpfSafeAsync(request.CPF);
                if (client == null || client.Id != id)
                {
                    throw new KeyNotFoundException("Cliente não encontrado");
                }

                // Atualizar campos
                client.Name = request.Name;
                client.Email = request.Email;
                client.Phone = request.Phone;

                await _clientRepository.UpdateClientAsync(client);

                return MapToClientResponse(client);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao atualizar cliente");
                throw;
            }
        }

        public async Task DeleteClientAsync(int id)
        {
            try
            {
                await _clientRepository.DeleteClientAsync(id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao excluir cliente");
                throw;
            }
        }

        private ClientResponse MapToClientResponse(Client client)
        {
            return new ClientResponse
            {
                Id = client.Id,
                Name = client.Name,
                CPF = client.CPF,
                Email = client.Email,
                Phone = client.Phone,
                CreatedAt = client.CreatedAt,
                IsActive = client.IsActive
            };
        }
    }
}
