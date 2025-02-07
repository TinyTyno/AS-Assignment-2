namespace AS_Assignment_2.Models
{
    using System;

    namespace AS_Assignment_2.Models
    {
        public class SendGridSettings
        {
            public string ApiKey { get; set; }
            public string FromEmail { get; set; }
            public string FromName { get; set; }
        }

        public interface IEmailService
        {
            Task SendOtpEmailAsync(string email, string otpCode);
            Task SendPasswordResetEmailAsync(string email, string resetLink);
        }
    }
}
