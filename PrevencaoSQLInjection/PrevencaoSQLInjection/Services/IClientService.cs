using PrevencaoSQLInjection.DTOs.Clients;

namespace PrevencaoSQLInjection.Services
{
    public interface IClientService
    {
        Task<ClientResponse> GetClientByCpfSafeAsync(string cpf);
        Task<ClientResponse> GetClientByCpfUnsafeAsync(string cpf);
        Task<IEnumerable<ClientResponse>> SearchClientsSafeAsync(ClientSearchRequest request);
        Task<IEnumerable<ClientResponse>> SearchClientsUnsafeAsync(ClientSearchRequest request);
        Task<ClientResponse> CreateClientAsync(ClientCreateRequest request);
        Task<ClientResponse> UpdateClientAsync(int id, ClientCreateRequest request);
        Task DeleteClientAsync(int id);
    }

    public class ClientSearchRequest
    {
        public string Name { get; set; }
        public string CPF { get; set; }
        public string Email { get; set; }
    }
}
