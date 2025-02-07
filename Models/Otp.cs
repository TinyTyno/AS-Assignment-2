namespace AS_Assignment_2.Models
{
    public class Otp
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string Code { get; set; }
        public DateTime Expiry { get; set; }
    }
}
