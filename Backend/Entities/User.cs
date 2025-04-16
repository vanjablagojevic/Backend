namespace Backend.Entities
{
    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; }   
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
       
        public int FailedLoginAttempts { get; set; } = 0;
        public DateTime? LockoutEnd { get; set; }
        public string Role { get; set; } = "User";
        public bool IsActive { get; set; } = true;

        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Address { get; set; }
        public DateTime? DateOfBirth { get; set; }
    }

}
