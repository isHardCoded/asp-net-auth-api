using System.Security.Claims;
using authApi.Data;
using authApi.DTOs;
using authApi.Models;
using authApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace authApi.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
  private readonly AppDbContext _db;
  private readonly PasswordService _passwordService;
  private readonly JwtService _jwtService;

  public AuthController(AppDbContext db, PasswordService passwordService, JwtService jwtService)
  {
    _db = db;
    _passwordService = passwordService;
    _jwtService = jwtService;
  }

  [HttpPost("register")]
  [AllowAnonymous]
  public async Task<IActionResult> Register(RegisterRequest request)
  {
    var exists = await _db.Users.AnyAsync(user => user.Email == request.Email);

    if (exists)
    {
      return BadRequest("Пользователь с таким Email уже существует");
    }

    var user = new User
    {
      Email = request.Email,
      PasswordHash = _passwordService.HashPassword(request.Password)
    };

    _db.Users.Add(user);
    await _db.SaveChangesAsync();

    return Ok("Пользовтель создан");
  }
  // login

  [HttpPost("login")]
  [AllowAnonymous]
  public async Task<ActionResult<AuthResponse>> Login(LoginRequest request)
  {
    var user = await _db.Users.FirstOrDefaultAsync(user => user.Email == request.Email);

    if (user == null)
    {
      return Unauthorized("Неверный email или пароль");
    }

    var valid = _passwordService.VerifyPassword(request.Password, user.PasswordHash);

    if (!valid)
    {
      return Unauthorized("Неверный email или пароль");
    }

    var response = await IssueTokensAsync(user);

    return Ok(response);
  }

  // me
  [HttpGet("me")]
  [Authorize]
  public async Task<IActionResult> Me()
  {
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

    if (!int.TryParse(userId, out var id))
    {
      return Unauthorized();
    }

    var user = await _db.Users.FindAsync(id);

    if (user == null)
    {
      return Unauthorized();
    }

    return Ok(new
    {
      user.Id,
      user.Email,
      user.Role,
      user.CreatedAt
    });
  }

    private async Task<AuthResponse> IssueTokensAsync(User user, RefreshToken? oldToken = null)
  {
    var accessToken = _jwtService.CreateToken(user);
    var refreshToken = _jwtService.CreateRefreshToken();
    var refreshTokenHash = _jwtService.HashToken(refreshToken);

    // Ротация: если это обновление, отзываем старый токен
    if (oldToken != null)
    {
      oldToken.RevokedAt = DateTime.UtcNow;
      oldToken.ReplacedByTokenHash = refreshTokenHash;
    }

    _db.RefreshTokens.Add(new RefreshToken
    {
      TokenHash = refreshTokenHash,   // в БД только хэш
      UserId = user.Id,
      ExpiresAt = _jwtService.GetRefreshTokenExpiry()
    });

    await _db.SaveChangesAsync();

    return new AuthResponse
    {
      AccessToken = accessToken,
      RefreshToken = refreshToken,    // клиенту отдаём сам токен
      Email = user.Email,
      Role = user.Role
    };
  }

  private async Task RevokeAllUserTokensAsync(int userId)
  {
    var activeTokens = await _db.RefreshTokens
      .Where(token => token.UserId == userId && token.RevokedAt == null)
      .ToListAsync();

    foreach (var token in activeTokens)
    {
      token.RevokedAt = DateTime.UtcNow;
    }

    await _db.SaveChangesAsync();
  }

  [HttpPost("refresh")]
  [AllowAnonymous]
  public async Task<ActionResult<AuthResponse>> Refresh(RefreshRequest request)
  {
    var tokenHash = _jwtService.HashToken(request.RefreshToken);

    var storedToken = await _db.RefreshTokens
      .Include(token => token.User)
      .FirstOrDefaultAsync(token => token.TokenHash == tokenHash);

    if (storedToken == null)
    {
      return Unauthorized("Недействительный refresh-токен");
    }

    // Токен уже отозван, но им снова пытаются воспользоваться.
    // Значит, его украли: отзываем ВСЕ сессии пользователя.
    if (storedToken.IsRevoked)
    {
      await RevokeAllUserTokensAsync(storedToken.UserId);
      return Unauthorized("Refresh-токен уже использован. Все сессии завершены");
    }

    if (storedToken.IsExpired)
    {
      return Unauthorized("Срок действия refresh-токена истёк");
    }

    var response = await IssueTokensAsync(storedToken.User, storedToken);

    return Ok(response);
  }

    [HttpPost("logout")]
  [AllowAnonymous]
  public async Task<IActionResult> Logout(RefreshRequest request)
  {
    var tokenHash = _jwtService.HashToken(request.RefreshToken);

    var storedToken = await _db.RefreshTokens
      .FirstOrDefaultAsync(token => token.TokenHash == tokenHash);

    if (storedToken != null && storedToken.IsActive)
    {
      storedToken.RevokedAt = DateTime.UtcNow;
      await _db.SaveChangesAsync();
    }

    return NoContent();
  }
}