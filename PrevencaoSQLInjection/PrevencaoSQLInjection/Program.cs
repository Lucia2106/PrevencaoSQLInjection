using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using PrevencaoSQLInjection.Data;
using PrevencaoSQLInjection.Data.Entities;
using PrevencaoSQLInjection.Repositories.Implementations;
using PrevencaoSQLInjection.Repositories.Interfaces;
using PrevencaoSQLInjection.Services;
using PrevencaoSQLInjection.Services.Security;
using SQLInjectionPreventionDemo.Data;
using SQLInjectionPreventionDemo.Repositories.Implementations;
using SQLInjectionPreventionDemo.Repositories.Interfaces;
using SQLInjectionPreventionDemo.Services;
using SQLInjectionPreventionDemo.Services.Security;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Configure DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Register repositories
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IClientRepository, ClientRepository>();

// Register services
builder.Services.AddScoped<IClientService, ClientService>();
builder.Services.AddScoped<IInputValidator, InputValidator>();
builder.Services.AddScoped<ISqlInjectionDetector, SqlInjectionDetector>();

// Configure JWT Authentication
var jwtKey = builder.Configuration["Jwt:Key"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ClockSkew = TimeSpan.Zero
    };
});

// Configure Authorization
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireClaim("role", "admin"));

    options.AddPolicy("UserOnly", policy =>
        policy.RequireClaim("role", "user"));
});

// Configure Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "SQL Injection Prevention Demo API",
        Version = "v1",
        Description = "Demonstração de técnicas de prevenção de SQL Injection"
    });

    // Add JWT Authentication to Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", builder =>
    {
        builder.AllowAnyOrigin()
               .AllowAnyMethod()
               .AllowAnyHeader();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "SQL Injection Prevention Demo API v1");
        c.RoutePrefix = string.Empty; // Set Swagger UI at the root
    });

    // Seed database in development
    using (var scope = app.Services.CreateScope())
    {
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        dbContext.Database.EnsureCreated();

        // Seed initial data if needed
        await SeedDatabase(dbContext, builder.Configuration);
    }
}

app.UseHttpsRedirection();

app.UseCors("AllowAll");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

async Task SeedDatabase(ApplicationDbContext context, IConfiguration configuration)
{
    if (!context.Users.Any())
    {
        // Create default admin user
        var salt = GenerateSalt();
        var passwordHash = GeneratePbkdf2Hash("Admin@123", salt, configuration);

        var adminUser = new User
        {
            Login = "admin",
            Email = "admin@demo.com",
            PasswordHash = passwordHash,
            Salt = salt,
            CreatedAt = DateTime.UtcNow,
            FailedLoginAttempts = 0,
            IsLocked = false
        };

        context.Users.Add(adminUser);

        // Create some test clients
        var clients = new List<Client>
        {
            new Client
            {
                Name = "João Silva",
                CPF = "123.456.789-00",
                Email = "joao.silva@email.com",
                Phone = "(11) 99999-9999",
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            },
            new Client
            {
                Name = "Maria Santos",
                CPF = "987.654.321-00",
                Email = "maria.santos@email.com",
                Phone = "(21) 98888-8888",
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            }
        };

        context.Clients.AddRange(clients);

        await context.SaveChangesAsync();
    }
}

string GenerateSalt()
{
    var saltBytes = new byte[16];
    using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
    {
        rng.GetBytes(saltBytes);
    }
    return Convert.ToBase64String(saltBytes);
}

string GeneratePbkdf2Hash(string password, string salt, IConfiguration configuration)
{
    var saltBytes = Convert.FromBase64String(salt);
    var iterations = configuration.GetValue<int>("Security:PBKDF2Iterations");

    using (var pbkdf2 = new System.Security.Cryptography.Rfc2898DeriveBytes(
        password, saltBytes, iterations, System.Security.Cryptography.HashAlgorithmName.SHA256))
    {
        var hashBytes = pbkdf2.GetBytes(32);
        return Convert.ToBase64String(hashBytes);
    }
}