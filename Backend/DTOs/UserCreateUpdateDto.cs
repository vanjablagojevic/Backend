using System.ComponentModel.DataAnnotations;
namespace Backend.DTOs;
public class UserCreateUpdateDto
{
    [Required(ErrorMessage = "Email je obavezan.")]
    [EmailAddress(ErrorMessage = "Email nije validan.")]
    public string Email { get; set; }

    [MinLength(6, ErrorMessage = "Lozinka mora imati barem 6 karaktera.")]
    public string? Password { get; set; } // Može biti opcionalna kod izmjene

    [Required(ErrorMessage = "Uloga je obavezna.")]
    public string Role { get; set; }

    public bool IsActive { get; set; }
}
