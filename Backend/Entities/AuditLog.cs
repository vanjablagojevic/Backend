namespace Backend.Entities
{
    public class AuditLog
    {
        public int Id { get; set; }
        public string TableName { get; set; }
        public string Action { get; set; } 
        public string ChangedBy { get; set; }
        public DateTime ChangedAt { get; set; }
        public string Data { get; set; } 
    }

}
