using System.ComponentModel.DataAnnotations;

namespace PrevencaoSQLInjection.Data.Entities
{
    public class Client
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(100)]
        public string Name { get; set; }

        [Required]
        [MaxLength(14)]
        public string CPF { get; set; }

        [EmailAddress]
        [MaxLength(100)]
        public string Email { get; set; }

        [MaxLength(15)]
        public string Phone { get; set; }

        public DateTime CreatedAt { get; set; }
        public bool IsActive { get; set; }
    }
}
