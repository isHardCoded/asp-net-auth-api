using System.Security.Claims;
using authApi.Data;
using authApi.DTOs;
using authApi.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace authApi.Controllers;

[ApiController]
[Route("api/users")]
[Authorize]
public class UsersController : ControllerBase
{
  private readonly AppDbContext _db;

  public UsersController(AppDbContext db)
  {
    _db = db;
  }

  // Список пользователей: менеджер и админ (через политику)
  [HttpGet]
  [Authorize(Policy = Policies.ManagerOrAdmin)]
  public async Task<IActionResult> GetAll()
  {
    var users = await _db.Users
      .Select(user => new { user.Id, user.Email, user.Role, user.CreatedAt })
      .ToListAsync();

    return Ok(users);
  }

  // Смена роли: только админ (через роль напрямую)
  [HttpPut("{id:int}/role")]
  [Authorize(Roles = Roles.Admin)]
  public async Task<IActionResult> ChangeRole(int id, ChangeRoleRequest request)
  {
    if (!Roles.All.Contains(request.Role))
    {
      return BadRequest($"Неизвестная роль. Допустимые: {string.Join(", ", Roles.All)}");
    }

    if (id == GetCurrentUserId())
    {
      return BadRequest("Нельзя изменить роль самому себе");
    }

    var user = await _db.Users.FindAsync(id);

    if (user == null)
    {
      return NotFound();
    }

    user.Role = request.Role;
    await _db.SaveChangesAsync();

    return Ok(new { user.Id, user.Email, user.Role });
  }

  // Удаление пользователя: только админ (через политику)
  [HttpDelete("{id:int}")]
  [Authorize(Policy = Policies.AdminOnly)]
  public async Task<IActionResult> Delete(int id)
  {
    if (id == GetCurrentUserId())
    {
      return BadRequest("Нельзя удалить самого себя");
    }

    var user = await _db.Users.FindAsync(id);

    if (user == null)
    {
      return NotFound();
    }

    // Удаляем и все refresh-токены пользователя
    var tokens = await _db.RefreshTokens
      .Where(token => token.UserId == id)
      .ToListAsync();

    _db.RefreshTokens.RemoveRange(tokens);
    _db.Users.Remove(user);
    await _db.SaveChangesAsync();

    return NoContent();
  }

  private int GetCurrentUserId()
  {
    return int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
  }
}