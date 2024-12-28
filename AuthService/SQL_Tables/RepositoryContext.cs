using AuthService.SQL_Models;
using Microsoft.EntityFrameworkCore;

public class RepositoryContext : DbContext
{
    public RepositoryContext(DbContextOptions<RepositoryContext> options) : base(options) { }
    public DbSet<sqlAccountInfo>? AccountInfo { get; set; }
    public DbSet<sqlAccessToken>? AccessToken { get; set; }
    public DbSet<sqlVerifyCodes>? VerifyCodes { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
    }
}