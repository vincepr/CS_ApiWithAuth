using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace ApiWithAuth.Context
{
    public class UsersContext : IdentityUserContext<IdentityUser>
    {
        private readonly IConfiguration _config;    // the config from our appsettings so we can get the ConnectionString
        public UsersContext(DbContextOptions<UsersContext> options, IConfiguration config)
            : base (options)
        {
            _config = config;
        }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            var conn = _config.GetConnectionString("ApiWithAuthDbConnStr");
            optionsBuilder.UseSqlServer(conn);
            // atm using the local db insteand (since no docker at this computer available)
            // BEST PRACTICE wouldbe to move this out to user secrets
            //optionsBuilder.UseNpgsql("Host=localhost;Database=postgres;Username=postgres;Password=mysecretpassword");
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
        }
    }
}
