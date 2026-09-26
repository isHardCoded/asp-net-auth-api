namespace authApi.Security;

public static class Roles
{
  public const string Admin = "Admin";
  public const string Manager = "Manager";
  public const string User = "User";

  public static readonly string[] All = { Admin, Manager, User };
}