using System.ComponentModel.DataAnnotations;

namespace PrevencaoSQLInjection.DTOs.Auth
{
    public class LoginRequest
    {
        [Required(ErrorMessage = "Login é obrigatório")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Login deve ter entre 3 e 50 caracteres")]
        public string Login { get; set; }

        [Required(ErrorMessage = "Senha é obrigatória")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Senha deve ter no mínimo 6 caracteres")]
        public string Password { get; set; }
    }

    public class LoginResponse
    {
        public string Token { get; set; }
        public DateTime ExpiresAt { get; set; }
        public UserInfo User { get; set; }
    }

    public class UserInfo
    {
        public int Id { get; set; }
        public string Login { get; set; }
        public string Email { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
