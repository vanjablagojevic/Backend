using Backend.Data;
using Backend.DTOs;
using Backend.Entities;
using Backend.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Backend.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly AppDbContext _context;

        public UsersController(AppDbContext context)
        {
            _context = context;
        }

        // GET: api/users
        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<IEnumerable<User>>> GetUsers()
        {
            return await _context.Users.ToListAsync();
        }

        // GET: api/users/5
        [HttpGet("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<User>> GetUser(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();
            return user;
        }

        // POST: api/users
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<User>> CreateUser(UserCreateUpdateDto dto)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            if (await _context.Users.AnyAsync(u => u.Email == dto.Email))
                return BadRequest("Email već postoji.");

            using var hmac = new HMACSHA512();
            var user = new User
            {
                Email = dto.Email,
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(dto.Password)),
                PasswordSalt = hmac.Key,
                Role = dto.Role,
                IsActive = true
            };

            _context.Users.Add(user);

            var log = new AuditLog
            {
                TableName = "User",
                Action = "INSERT",
                ChangedBy = User.FindFirst(ClaimTypes.Email).Value,
                ChangedAt = DateTime.Now,
                Data = JsonConvert.SerializeObject(user)
            };
            _context.AuditLogs.Add(log);
            await _context.SaveChangesAsync();
            return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
        }

        [HttpPut("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateUser(int id, UserCreateUpdateDto dto)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();

            bool hasChanges =
                user.Email != dto.Email ||
                user.Role != dto.Role ||
                user.IsActive != dto.IsActive;

            if (!hasChanges)
                return NoContent();

            if (user.Email != dto.Email && await _context.Users.AnyAsync(u => u.Email == dto.Email))
                return BadRequest("Email već postoji.");

            // Snimanje prethodne verziju i audit log samo ako ima izmjena
            var previousVersion = new UserVersion
            {
                UserId = user.Id,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Adress = user.Address,
                DateOfBirth = user.DateOfBirth,
                Role = user.Role,
                IsActive = user.IsActive,
                ChangedAt = DateTime.Now,
                ChangedBy = User.FindFirst(ClaimTypes.Email)?.Value
            };
            _context.UserVersions.Add(previousVersion);

            var log = new AuditLog
            {
                TableName = "User",
                Action = "UPDATE",
                ChangedBy = User.FindFirst(ClaimTypes.Email)?.Value,
                ChangedAt = DateTime.Now,
                Data = JsonConvert.SerializeObject(user)
            };
            _context.AuditLogs.Add(log);

            user.Email = dto.Email;
            user.Role = dto.Role;
            user.IsActive = dto.IsActive;

            if (!string.IsNullOrWhiteSpace(dto.Password))
            {
                using var hmac = new HMACSHA512();
                user.PasswordSalt = hmac.Key;
                user.PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(dto.Password));
            }

            await _context.SaveChangesAsync();
            return NoContent();
        }


        // DELETE: api/users/5
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var user = await _context.Users.FindAsync(id);

            if (user == null) return NotFound();

            var log = new AuditLog
            {
                TableName = "User",
                Action = "DELETE",
                ChangedBy = User.FindFirst(ClaimTypes.Email).Value,
                ChangedAt = DateTime.Now,
                Data = JsonConvert.SerializeObject(user)
            };
            _context.AuditLogs.Add(log);

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        [HttpPost("{userId}/revert/{versionId}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> RevertUser(int userId, int versionId)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null) return NotFound();

            var version = await _context.UserVersions
                .FirstOrDefaultAsync(v => v.UserId == userId && v.Id == versionId);

            if (version == null)
                return NotFound();

            var newVersion = new UserVersion
            {
                UserId = version.UserId,
                FirstName = version.FirstName,
                LastName = version.LastName,
                Adress = version.Adress,
                DateOfBirth = version.DateOfBirth,
                Role = version.Role,
                IsActive= version.IsActive,
                Email = version.Email,
                ChangedAt = DateTime.Now,
                ChangedBy = User.FindFirst(ClaimTypes.Email).Value
            };

            _context.UserVersions.Add(newVersion);

            var log = new AuditLog
            {
                TableName = "User",
                Action = "REVERT",
                ChangedBy = User.FindFirst(ClaimTypes.Email).Value,
                ChangedAt = DateTime.Now,
                Data = JsonConvert.SerializeObject(version)
            };
            _context.AuditLogs.Add(log);

            user.Email = version.Email;
            user.FirstName = version.FirstName;
            user.LastName = version.LastName;
            user.Address = version.Adress;
            user.Role=version.Role;
            user.IsActive = version.IsActive;
            user.DateOfBirth = version.DateOfBirth;

            await _context.SaveChangesAsync();
            return Ok();
        }

    
        // GET: api/users/profile
        [HttpGet("profile")]
        public async Task<ActionResult<UpdateProfileDto>> GetProfile()
        {
            var userId = User.GetUserId();
            var user = await _context.Users.FindAsync(userId);

            if (user == null)
                return NotFound("Korisnik nije pronađen.");

            var dto = new UpdateProfileDto
            {
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Address = user.Address,
                DateOfBirth = user.DateOfBirth
            };

            return Ok(dto);
        }

        // PUT: api/users/profile
        [HttpPut("profile")]
        public async Task<IActionResult> UpdateProfile(UpdateProfileDto dto)
        {
            var userId = User.GetUserId();
            var user = await _context.Users.FindAsync(userId);

            bool hasChanges =
            user.Email != dto.Email ||
            user.FirstName != dto.FirstName ||
            user.LastName != dto.LastName ||
            user.Address != dto.Address ||
            user.DateOfBirth != dto.DateOfBirth;

            if (!hasChanges)
                return NoContent();

            if (user == null)
                return NotFound("Korisnik nije pronađen.");

            if (user.Email != dto.Email && await _context.Users.AnyAsync(u => u.Email == dto.Email))
                return BadRequest("Email već postoji.");

            var previousVersion = new UserVersion
            {
                UserId = user.Id,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Adress = user.Address,
                DateOfBirth = user.DateOfBirth,
                Role = user.Role,
                IsActive = user.IsActive,
                ChangedAt = DateTime.UtcNow,
                ChangedBy = User.FindFirst(ClaimTypes.Email)?.Value
            }; 

            _context.UserVersions.Add(previousVersion);

            var log = new AuditLog
            {
                TableName = "User",
                Action = "UPDATE",
                ChangedBy = User.FindFirst(ClaimTypes.Email)?.Value,
                ChangedAt = DateTime.UtcNow,
                Data = JsonConvert.SerializeObject(user)
            };
            _context.AuditLogs.Add(log);


            user.Email = dto.Email;
            user.FirstName = dto.FirstName;
            user.LastName = dto.LastName;
            user.Address = dto.Address;
            user.DateOfBirth = dto.DateOfBirth;

            await _context.SaveChangesAsync();
            return Ok("Profil uspješno ažuriran.");
        }


        // GET: api/users/statistics
        [HttpGet("statistics")]
        public IActionResult GetUserStatistics()
        {
            var activeUsers = _context.Users.Count(u => u.IsActive);
            var inactiveUsers = _context.Users.Count(u => !u.IsActive);
            return Ok(new { activeUsers, inactiveUsers });
        }

        [Authorize]
        [HttpPut("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userId = User.GetUserId();
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
                return NotFound("Korisnik nije pronađen.");

            // Ako korisnik nije poslao trenutnu lozinku, ne mijenjamo lozinku
            if (!string.IsNullOrEmpty(dto.CurrentPassword) && !string.IsNullOrEmpty(dto.NewPassword))
            {
                using var hmac = new HMACSHA512(user.PasswordSalt);
                var currentHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(dto.CurrentPassword));
                if (!currentHash.SequenceEqual(user.PasswordHash))
                    return BadRequest("Trenutna lozinka nije tačna.");

                using var newHmac = new HMACSHA512();
                user.PasswordSalt = newHmac.Key;
                user.PasswordHash = newHmac.ComputeHash(Encoding.UTF8.GetBytes(dto.NewPassword));
            }

            await _context.SaveChangesAsync();
            return Ok("Lozinka je uspješno promijenjena.");


        }

        [HttpGet("user-history/{userId}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetUserHistory(int userId, [FromQuery] int page = 1)
        {
            var totalCount = await _context.UserVersions
                .Where(u => u.UserId == userId)
                .CountAsync();

            var history = await _context.UserVersions
                .Where(u => u.UserId == userId)
                .OrderByDescending(u => u.ChangedAt)
                .Skip((page - 1) * 5)
                .Take(5)
                .ToListAsync();

            var result = new
            {
                TotalCount = totalCount,
                CurrentPage = page,
                PageSize = 5,
                TotalPages = (int)Math.Ceiling((double)totalCount / 5),
                History = history
            };

            return Ok(result);
        }

        [HttpGet("audit-logs")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetAuditLogs([FromQuery] int page = 1)
        {
            const int pageSize = 7;

            if (page < 1)
            {
                return BadRequest("Stranica mora biti 1 najmanje.");
            }

            var totalLogs = await _context.AuditLogs.CountAsync();

            var logs = await _context.AuditLogs
                .OrderByDescending(log => log.ChangedAt)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return Ok(new
            {
                TotalCount = totalLogs,
                Page = page,
                PageSize = pageSize,
                Logs = logs
            });
        }
    }
}
