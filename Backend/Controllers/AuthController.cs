using Backend.Data;
using Backend.DTOs;
using Backend.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _config;

        public AuthController(AppDbContext context, IConfiguration config)
        {
            _context = context;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto dto)
        {
            if (await _context.Users.AnyAsync(u => u.Email == dto.Email))
                return BadRequest("Korisnik već postoji!");

            CreatePasswordHash(dto.Password, out byte[] passwordHash, out byte[] passwordSalt);

            var isFirstUser = !await _context.Users.AnyAsync();
            var role = isFirstUser ? "Admin" : "User";

            var user = new User
            {
                Email = dto.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                Role = role,
                IsActive = true
            };

            _context.Users.Add(user);

            var log = new AuditLog
            {
                TableName = "User",
                Action = "REGISTER",
                ChangedBy = user.Email,
                ChangedAt = DateTime.Now,
                Data = JsonConvert.SerializeObject(user)
            };
            _context.AuditLogs.Add(log);
            await _context.SaveChangesAsync();

            return Ok("Korisnik je registrovan.");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto dto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null)
                return Unauthorized("Nevažeći kredencijali");

            //Provjera za aktivan/neaktivan profil
            if (!user.IsActive)
                return BadRequest("Vaš profil je neaktivan. Obratite se administratoru.");

            // Provjeri da li je korisnik zaključan
            if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow)
            {
                var remaining = user.LockoutEnd.Value.Subtract(DateTime.UtcNow).Minutes;
                return BadRequest($"Račun je zaključan. Probajte opet za {remaining} minuta.");
            }

            // Provjera lozinke
            if (!VerifyPassword(dto.Password, user.PasswordHash, user.PasswordSalt))
            {
                user.FailedLoginAttempts++;

                // Ako je 5. pokušaj neuspješan — zaključaj
                if (user.FailedLoginAttempts >= 5)
                {
                    user.LockoutEnd = DateTime.UtcNow.AddMinutes(5);
                    user.FailedLoginAttempts = 0; // resetuj nakon zaključavanja
                    await _context.SaveChangesAsync();
                    return BadRequest("Račun je zaključan zbog previše pokušaja nevažeće prijave. Pokušajte ponovo za 5 minuta.");
                }

                await _context.SaveChangesAsync();
                return Unauthorized("Nevažeći kredencijali");
            }

            // Resetuj ako je login uspješan
            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            await _context.SaveChangesAsync();

            var token = GenerateJwtToken(user);
            return Ok(new { token });
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512();
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        }

        private bool VerifyPassword(string password, byte[] storedHash, byte[] storedSalt)
        {
            using var hmac = new HMACSHA512(storedSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            return computedHash.SequenceEqual(storedHash);
        }

        private string GenerateJwtToken(User user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        
            var claims = new[]
              {
             new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
             new Claim(ClaimTypes.Email, user.Email),
             new Claim(ClaimTypes.Role, user.Role)
                };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}
