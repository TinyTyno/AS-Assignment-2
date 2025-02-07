namespace AS_Assignment_2.Models
{
    public class ErrorViewModel
    {
        public int StatusCode { get; set; }
        public string? ErrorMessage { get; set; }
        public string? RequestId { get; set; }
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
    }
}