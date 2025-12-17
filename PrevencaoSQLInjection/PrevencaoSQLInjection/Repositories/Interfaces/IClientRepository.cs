using PrevencaoSQLInjection.Data.Entities;

namespace PrevencaoSQLInjection.Repositories.Interfaces
{
    public interface IClientRepository
    {
        Task<Client> GetClientByCpfSafeAsync(string cpf);
        Task<Client> GetClientByCpfUnsafeAsync(string cpf);
        Task<Client> GetClientByCpfStoredProcedureAsync(string cpf);
        Task<IEnumerable<Client>> SearchClientsSafeAsync(string name, string cpf, string email);
        Task<IEnumerable<Client>> SearchClientsUnsafeAsync(string name, string cpf, string email);
        Task<int> CreateClientAsync(Client client);
        Task UpdateClientAsync(Client client);
        Task DeleteClientAsync(int id);
        Task<bool> ClientExistsByCpfAsync(string cpf);
        Task<bool> ClientExistsByEmailAsync(string email);
    }
}
