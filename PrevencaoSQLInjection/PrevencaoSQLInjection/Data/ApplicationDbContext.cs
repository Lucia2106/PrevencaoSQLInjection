using PrevencaoSQLInjection.Data.Entities;
using System.Collections.Generic;
using System.Reflection.Emit;

namespace PrevencaoSQLInjection.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {

        }

        public DbSet<User> Users { get; set; }
        public DbSet<Client> Clients { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<User>(entity =>
            {
                entity.HasIndex(u => u.Login).IsUnique();
                entity.HasIndex(u => u.Email).IsUnique();
                entity.Property(u => u.CreatedAt).HasDefaultValueSql("GETDATE()");
            });

            modelBuilder.Entity<Client>(entity =>
            {
                entity.HasIndex(c => c.CPF).IsUnique();
                entity.HasIndex(c => c.Email).IsUnique();
                entity.Property(c => c.CreatedAt).HasDefaultValueSql("GETDATE()");
                entity.Property(c => c.IsActive).HasDefaultValue(true);
            });
        }
    }
}
