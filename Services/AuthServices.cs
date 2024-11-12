using Microsoft.EntityFrameworkCore;
using SimpleFormApp.Data;
using SimpleFormApp.Models;


namespace SimpleFormApp.Services;

public interface IAuthService
{
    Task<bool> ValidateUserAsync(string username, string password);
    Task<User> GetUserByUsernameAsync(string username);
    string HashPassword(string password);
}

public class AuthService : IAuthService
{
    private readonly ApplicationDbContext _context;

    public AuthService(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<bool> ValidateUserAsync(string username, string password)
    {
        var user = await GetUserByUsernameAsync(username);
        if (user == null) return false;

        return BCrypt.Net.BCrypt.Verify(password, user.Password);
    }

    public async Task<User> GetUserByUsernameAsync(string username)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Username == username);
    }

    public string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password);
    }
}