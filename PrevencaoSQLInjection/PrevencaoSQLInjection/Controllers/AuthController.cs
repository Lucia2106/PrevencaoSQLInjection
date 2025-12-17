using Microsoft.AspNetCore.Mvc;
using PrevencaoSQLInjection.Data.Entities;
using PrevencaoSQLInjection.DTOs.Auth;
using PrevencaoSQLInjection.Repositories.Interfaces;
using PrevencaoSQLInjection.Services.Security;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace PrevencaoSQLInjection.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IUserRepository _userRepository;
        private readonly IConfiguration _configuration;
        private readonly IInputValidator _inputValidator;
        private readonly ISqlInjectionDetector _sqlInjectionDetector;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IUserRepository userRepository,
            IConfiguration configuration,
            IInputValidator inputValidator,
            ISqlInjectionDetector sqlInjectionDetector,
            ILogger<AuthController> logger)
        {
            _userRepository = userRepository;
            _configuration = configuration;
            _inputValidator = inputValidator;
            _sqlInjectionDetector = sqlInjectionDetector;
            _logger = logger;
        }

        [HttpPost("login-safe")]
        public async Task<ActionResult<LoginResponse>> LoginSafe(LoginRequest request)
        {
            try
            {
                // Validação de input
                if (!_inputValidator.ValidateLogin(request.Login))
                {
                    return BadRequest("Login inválido");
                }

                // Detecção de SQL Injection
                if (_sqlInjectionDetector.ContainsSqlInjection(request.Login) ||
                    _sqlInjectionDetector.ContainsSqlInjection(request.Password))
                {
                    _logger.LogWarning("Tentativa de SQL Injection detectada no login");
                    return Unauthorized("Credenciais inválidas");
                }

                // Buscar usuário usando método seguro
                var user = await _userRepository.GetUserByLoginSafeAsync(request.Login);

                if (user == null)
                {
                    // Simular mesmo tempo de resposta para evitar timing attacks
                    await Task.Delay(100);
                    return Unauthorized("Credenciais inválidas");
                }

                // Verificar se conta está bloqueada
                if (user.IsLocked && user.LockedUntil.HasValue && user.LockedUntil > DateTime.UtcNow)
                {
                    return Unauthorized($"Conta bloqueada até {user.LockedUntil.Value:dd/MM/yyyy HH:mm}");
                }

                // Verificar senha usando PBKDF2
                var passwordHash = GeneratePbkdf2Hash(request.Password, user.Salt);

                if (user.PasswordHash != passwordHash)
                {
                    // Incrementar tentativas falhas
                    user.FailedLoginAttempts++;

                    if (user.FailedLoginAttempts >= 3)
                    {
                        user.IsLocked = true;
                        user.LockedUntil = DateTime.UtcNow.AddMinutes(15);
                        _logger.LogWarning("Conta bloqueada após múltiplas tentativas falhas: {Login}", request.Login);
                    }

                    await _userRepository.UpdateUserAsync(user);
                    return Unauthorized("Credenciais inválidas");
                }

                // Login bem-sucedido
                user.LastLoginAt = DateTime.UtcNow;
                user.FailedLoginAttempts = 0;
                user.IsLocked = false;
                user.LockedUntil = null;

                await _userRepository.UpdateUserAsync(user);

                // Gerar token JWT
                var token = GenerateJwtToken(user);

                return Ok(new LoginResponse
                {
                    Token = token,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(60),
                    User = new UserInfo
                    {
                        Id = user.Id,
                        Login = user.Login,
                        Email = user.Email,
                        CreatedAt = user.CreatedAt
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro no login seguro");
                return StatusCode(500, "Erro interno do servidor");
            }
        }

        [HttpPost("login-unsafe")]
        public async Task<ActionResult<LoginResponse>> LoginUnsafe(LoginRequest request)
        {
            try
            {
                // MÉTODO VULNERÁVEL - APENAS PARA DEMONSTRAÇÃO
                // Buscar usuário usando método vulnerável
                var user = await _userRepository.GetUserByLoginUnsafeAsync(request.Login);

                if (user == null)
                {
                    return Unauthorized("Credenciais inválidas");
                }

                // Verificação de senha vulnerável (comparação direta)
                if (user.PasswordHash != request.Password) // SENHA EM TEXTO PURO - NUNCA FAÇA ISSO!
                {
                    return Unauthorized("Credenciais inválidas");
                }

                // Gerar token
                var token = GenerateJwtToken(user);

                return Ok(new LoginResponse
                {
                    Token = token,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(60),
                    User = new UserInfo
                    {
                        Id = user.Id,
                        Login = user.Login,
                        Email = user.Email,
                        CreatedAt = user.CreatedAt
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro no login vulnerável");
                return StatusCode(500, "Erro interno do servidor");
            }
        }

        [HttpPost("register")]
        public async Task<ActionResult> Register(RegisterRequest request)
        {
            try
            {
                // Validações
                if (!_inputValidator.ValidateLogin(request.Login))
                {
                    return BadRequest("Login inválido");
                }

                if (!_inputValidator.ValidateEmail(request.Email))
                {
                    return BadRequest("Email inválido");
                }

                if (request.Password.Length < 6)
                {
                    return BadRequest("Senha deve ter no mínimo 6 caracteres");
                }

                // Verificar se login já existe
                if (await _userRepository.LoginExistsAsync(request.Login))
                {
                    return Conflict("Login já está em uso");
                }

                // Verificar se email já existe
                if (await _userRepository.EmailExistsAsync(request.Email))
                {
                    return Conflict("Email já está em uso");
                }

                // Gerar salt único
                var salt = GenerateSalt();

                // Gerar hash da senha usando PBKDF2
                var passwordHash = GeneratePbkdf2Hash(request.Password, salt);

                // Criar usuário
                var user = new User
                {
                    Login = request.Login,
                    Email = request.Email,
                    PasswordHash = passwordHash,
                    Salt = salt,
                    CreatedAt = DateTime.UtcNow,
                    FailedLoginAttempts = 0,
                    IsLocked = false
                };

                await _userRepository.CreateUserAsync(user);

                return CreatedAtAction(nameof(LoginSafe), new { login = user.Login });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro no registro");
                return StatusCode(500, "Erro interno do servidor");
            }
        }

        private string GenerateJwtToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

            var credentials = new SigningCredentials(
                securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Login),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("userId", user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(60),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateSalt()
        {
            var saltBytes = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }
            return Convert.ToBase64String(saltBytes);
        }

        private string GeneratePbkdf2Hash(string password, string salt)
        {
            var saltBytes = Convert.FromBase64String(salt);
            var iterations = _configuration.GetValue<int>("Security:PBKDF2Iterations");

            using (var pbkdf2 = new Rfc2898DeriveBytes(
                password, saltBytes, iterations, HashAlgorithmName.SHA256))
            {
                var hashBytes = pbkdf2.GetBytes(32); // 256 bits
                return Convert.ToBase64String(hashBytes);
            }
        }
    }

    public class RegisterRequest
    {
        public string Login { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
