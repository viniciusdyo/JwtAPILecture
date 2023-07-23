using JwtAPILecture.Models;
using Microsoft.EntityFrameworkCore;

namespace JwtAPILecture.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {

        }

        public DbSet<Team> Teams { get; set; }
    }
}
