using System.Security.Cryptography;
using System.Text;

namespace authApi.Services;

public class PasswordService
{
  // petya123 -> asdnhcas98cdyaus
  
  public string HashPassword(string password)
  {
    using var sha = SHA256.Create();
    var bytes = Encoding.UTF8.GetBytes(password);
    var hash = sha.ComputeHash(bytes);

    return Convert.ToBase64String(hash);
  }

  public bool VerifyPassword(string password, string passwordHash)
  {
    return HashPassword(password) == passwordHash;
  }
}