namespace PrevencaoSQLInjection.Services.Security
{
    public interface IInputValidator
    {
        bool ValidateCpf(string cpf);
        bool ValidateEmail(string email);
        bool ValidateName(string name);
        bool ValidatePhone(string phone);
        bool ValidateLogin(string login);
        string SanitizeInput(string input);
    }
}
