using System.ComponentModel.DataAnnotations;

namespace Backend.DTOs
{
   public class ChangePasswordDto
      {
           
          public string? CurrentPassword { get; set; }

          [MinLength(6, ErrorMessage = "Nova lozinka mora imati najmanje 6 karaktera.")]
          public string? NewPassword { get; set; }

          [Compare("NewPassword", ErrorMessage = "Nova lozinka i potvrda lozinke se ne podudaraju.")]
          public string? ConfirmPassword { get; set; }
       }

}
