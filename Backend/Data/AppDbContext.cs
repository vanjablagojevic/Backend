using Backend.Entities;
using Microsoft.EntityFrameworkCore;

namespace Backend.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<UserVersion> UserVersions { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }
    }
}
