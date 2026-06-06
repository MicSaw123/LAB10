using Microsoft.EntityFrameworkCore;
using SecurityAudit.Domain;

namespace SecurityAudit.Database
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        public DbSet<AuditItem> Audits => Set<AuditItem>();
        public DbSet<User> Users => Set<User>();
    }
}
