namespace Backend.Entities
{
    public class UserVersion
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Adress { get; set; }
        public DateTime? DateOfBirth { get; set; }
        public string Role { get; set; }

        public DateTime ChangedAt { get; set; }
        public string ChangedBy { get; set; }

        public User User { get; set; }
    }

}
