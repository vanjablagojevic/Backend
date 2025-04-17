using System.ComponentModel.DataAnnotations;

namespace Backend.DTOs
{
    public class UpdateProfileDto
    {
        public string Email { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Address { get; set; }
        public DateTime? DateOfBirth { get; set; }

    }

}
