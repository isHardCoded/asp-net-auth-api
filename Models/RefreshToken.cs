namespace authApi.Models;

public class RefreshToken
{
  public int Id { get; set; }

  // Храним не сам токен, а его хэш (как с паролями)
  public string TokenHash { get; set; } = string.Empty;
  
  public int UserId { get; set; }
  public User User { get; set; } = null!;

  public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
  public DateTime ExpiresAt { get; set; }

  // Заполняется, когда токен отозван (logout или ротация)
  public DateTime? RevokedAt { get; set; }

  // Хэш токена, который пришёл на смену этому (цепочка ротации)
  public string? ReplacedByTokenHash { get; set; }

  public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
  public bool IsRevoked => RevokedAt != null;
  public bool IsActive => !IsRevoked && !IsExpired;
}