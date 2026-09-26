using authApi.Models;
using authApi.Security;
using authApi.Services;

namespace authApi.Data;

public static class DbSeeder
{
  public static void SeedAdmin(IServiceProvider services, IConfiguration configuration)
  {
    // DbContext зарегистрирован как Scoped, поэтому вне HTTP-запроса
    // нужно вручную создать область (scope)
    using var scope = services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var passwordService = scope.ServiceProvider.GetRequiredService<PasswordService>();

    if (db.Users.Any(user => user.Role == Roles.Admin))
    {
      return;
    }

    db.Users.Add(new User
    {
      Email = configuration["SeedAdmin:Email"]!,
      PasswordHash = passwordService.HashPassword(configuration["SeedAdmin:Password"]!),
      Role = Roles.Admin
    });

    db.SaveChanges();
  }
}