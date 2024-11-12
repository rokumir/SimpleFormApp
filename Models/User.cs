using System.ComponentModel.DataAnnotations;

namespace SimpleFormApp.Models;

public class User
{
    public int Id { get; set; }

    [Required]
    [Display(Name = "Full Name")]
    public required string FullName { get; set; }

    [Required]
    [Display(Name = "Username")]
    public required string Username { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public required string PasswordHash { get; set; }
}