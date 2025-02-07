using System;

namespace AS_Assignment_2.Models
{
    public class AuditLog
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string Activity { get; set; }
        public DateTime Timestamp { get; set; }
        public string Details { get; set; }
    }
}