using System.Text.RegularExpressions;

namespace PrevencaoSQLInjection.Services.Security
{
    public class InputValidator : IInputValidator
    {
        // Whitelist approach for validation
        private readonly Regex _cpfRegex = new(@"^\d{3}\.\d{3}\.\d{3}-\d{2}$",
            RegexOptions.Compiled);

        private readonly Regex _emailRegex = new(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            RegexOptions.Compiled);

        private readonly Regex _nameRegex = new(@"^[a-zA-ZÀ-ÿ\s']{2,100}$",
            RegexOptions.Compiled);

        private readonly Regex _phoneRegex = new(@"^\(\d{2}\)\s?\d{4,5}-\d{4}$",
            RegexOptions.Compiled);

        private readonly Regex _loginRegex = new(@"^[a-zA-Z0-9_]{3,50}$",
            RegexOptions.Compiled);

        // Blacklist for dangerous characters
        private readonly Regex _dangerousCharsRegex = new(@"[;'""\\--/*]|(\b(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)\b)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public bool ValidateCpf(string cpf)
        {
            if (string.IsNullOrWhiteSpace(cpf))
                return false;

            return _cpfRegex.IsMatch(cpf) && IsValidCpfDigits(cpf);
        }

        private bool IsValidCpfDigits(string cpf)
        {
            // Remove formatting
            var numbers = cpf.Replace(".", "").Replace("-", "");

            if (numbers.Length != 11 || numbers.All(c => c == numbers[0]))
                return false;

            return true;
        }

        public bool ValidateEmail(string email)
        {
            return !string.IsNullOrWhiteSpace(email) && _emailRegex.IsMatch(email);
        }

        public bool ValidateName(string name)
        {
            return !string.IsNullOrWhiteSpace(name) && _nameRegex.IsMatch(name);
        }

        public bool ValidatePhone(string phone)
        {
            return !string.IsNullOrWhiteSpace(phone) && _phoneRegex.IsMatch(phone);
        }

        public bool ValidateLogin(string login)
        {
            return !string.IsNullOrWhiteSpace(login) && _loginRegex.IsMatch(login);
        }

        public string SanitizeInput(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return input;

            // Remove potentially dangerous characters
            return _dangerousCharsRegex.Replace(input, "");
        }
    }
}
