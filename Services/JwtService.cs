using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using authApi.Models;
using System.Text;

namespace authApi.Services;

public class JwtService
{
  private readonly IConfiguration _configuration;

  public JwtService(IConfiguration configuration)
  {
    _configuration = configuration;
  }

  public string CreateToken(User user)
  {
    var key = _configuration["Jwt:Key"]!;
    var issuer = _configuration["Jwt:Issuer"];
    var audience = _configuration["Jwt:Audience"];
    var expiresMinutes = int.Parse(_configuration["Jwt:AccessTokenMinutes"]!);   // новое имя ключа

    var claims = new List<Claim>
    {
      new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
      new Claim(ClaimTypes.Email, user.Email),
      new Claim(ClaimTypes.Role, user.Role)
    };

    var credentials = new SigningCredentials(
      new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
      SecurityAlgorithms.HmacSha256
    );

    var token = new JwtSecurityToken(
      issuer: issuer,
      audience: audience,
      claims: claims,
      expires: DateTime.UtcNow.AddMinutes(expiresMinutes),
      signingCredentials: credentials
    );

    return new JwtSecurityTokenHandler().WriteToken(token);
  }

  // Криптостойкая случайная строка, а не Guid и не Random
  public string CreateRefreshToken()
  {
    var bytes = RandomNumberGenerator.GetBytes(64);
    return Convert.ToBase64String(bytes);
  }

  public string HashToken(string token)
  {
    var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
    return Convert.ToBase64String(bytes);
  }

  public DateTime GetRefreshTokenExpiry()
  {
    var days = int.Parse(_configuration["Jwt:RefreshTokenDays"]!);
    return DateTime.UtcNow.AddDays(days);
  }
}