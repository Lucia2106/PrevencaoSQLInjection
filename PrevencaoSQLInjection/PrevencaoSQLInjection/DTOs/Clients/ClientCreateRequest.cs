using System.ComponentModel.DataAnnotations;

namespace PrevencaoSQLInjection.DTOs.Clients
{
    public class ClientCreateRequest
    {
        [Required(ErrorMessage = "Nome é obrigatório")]
        [StringLength(100, MinimumLength = 2, ErrorMessage = "Nome deve ter entre 2 e 100 caracteres")]
        public string Name { get; set; }

        [Required(ErrorMessage = "CPF é obrigatório")]
        [RegularExpression(@"^\d{3}\.\d{3}\.\d{3}-\d{2}$", ErrorMessage = "CPF deve estar no formato 000.000.000-00")]
        public string CPF { get; set; }

        [EmailAddress(ErrorMessage = "Email inválido")]
        [StringLength(100, ErrorMessage = "Email deve ter no máximo 100 caracteres")]
        public string Email { get; set; }

        [RegularExpression(@"^\(\d{2}\)\s?\d{4,5}-\d{4}$", ErrorMessage = "Telefone deve estar no formato (00) 0000-0000 ou (00) 00000-0000")]
        public string Phone { get; set; }
    }

    public class ClientResponse
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string CPF { get; set; }
        public string Email { get; set; }
        public string Phone { get; set; }
        public DateTime CreatedAt { get; set; }
        public bool IsActive { get; set; }
    }
}
