using System.ComponentModel.DataAnnotations;

namespace SimpleFormApp.Models;

public class SignUpViewModel
{
    public string FullName { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
    public string ConfirmPassword { get; set; }
}