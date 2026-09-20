using Microsoft.EntityFrameworkCore;
using authApi.Models;

namespace authApi.Data;

public class AppDbContext : DbContext
{
  public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) {}

  public DbSet<User> Users => Set<User>();
}