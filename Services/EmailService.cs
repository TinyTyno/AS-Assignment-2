using Microsoft.Extensions.Options;
using System.Net.Mail;
using System.Net;
using AS_Assignment_2.Models.AS_Assignment_2.Models;
using System.Threading.Tasks;
using SendGrid;
using SendGrid.Helpers.Mail;
using Microsoft.Extensions.Options;

namespace AS_Assignment_2.Services
{
    public class SendGridEmailService : IEmailService
    {
        private readonly SendGridSettings _settings;

        public SendGridEmailService(IOptions<SendGridSettings> settings)
        {
            _settings = settings.Value;
        }

        public async Task SendOtpEmailAsync(string email, string otpCode)
        {
            var client = new SendGridClient(_settings.ApiKey);
            var from = new EmailAddress(_settings.FromEmail, _settings.FromName);
            var to = new EmailAddress(email);
            var subject = "Your Login Verification Code";
            var plainTextContent = $"Your OTP code is: {otpCode}";
            var htmlContent = $"<strong>Your OTP code is: {otpCode}</strong>";

            // Log email details
            Console.WriteLine("---------- Email Details ----------");
            Console.WriteLine($"From: {from.Email} ({from.Name})");
            Console.WriteLine($"To: {to.Email}");
            Console.WriteLine($"Subject: {subject}");
            Console.WriteLine($"Plain Text: {plainTextContent}");
            Console.WriteLine($"HTML Content: {htmlContent}");

            var msg = MailHelper.CreateSingleEmail(
                from, to, subject, plainTextContent, htmlContent);

            // Send email and capture response
            var response = await client.SendEmailAsync(msg);

            // Log SendGrid response details
            Console.WriteLine("\n---------- SendGrid Response ----------");
            Console.WriteLine($"Status Code: {(int)response.StatusCode} {response.StatusCode}");
            Console.WriteLine("Headers:");
            foreach (var header in response.Headers)
            {
                Console.WriteLine($"  {header.Key}: {header.Value}");
            }

            // Read and log the response body
            var responseBody = await response.Body.ReadAsStringAsync();
            Console.WriteLine($"Body: {responseBody}");
            Console.WriteLine("-------------------------------------\n");
        }

        public async Task SendPasswordResetEmailAsync(string email, string resetLink)
        {
            var client = new SendGridClient(_settings.ApiKey);
            var from = new EmailAddress(_settings.FromEmail, _settings.FromName);
            var to = new EmailAddress(email);
            var subject = "Password Reset Request";
            var plainTextContent = $"Please click the following link to reset your password: {resetLink}";
            var htmlContent = $"<strong>Please click the following link to reset your password: <a href=\"{resetLink}\">{resetLink}</a></strong>";

            Console.WriteLine("---------- Email Details ----------");
            Console.WriteLine($"From: {from.Email} ({from.Name})");
            Console.WriteLine($"To: {to.Email}");
            Console.WriteLine($"Subject: {subject}");
            Console.WriteLine($"Plain Text: {plainTextContent}");
            Console.WriteLine($"HTML Content: {htmlContent}");
            Console.WriteLine("-------------------------------------\n");

            var msg = MailHelper.CreateSingleEmail(
                from, to, subject, plainTextContent, htmlContent);

            var response = await client.SendEmailAsync(msg);

            Console.WriteLine("\n---------- SendGrid Response ----------");
            Console.WriteLine($"Status Code: {(int)response.StatusCode} {response.StatusCode}");
            Console.WriteLine("Headers:");
            foreach (var header in response.Headers)
            {
                Console.WriteLine($"  {header.Key}: {header.Value}");
            }

            var responseBody = await response.Body.ReadAsStringAsync();
            Console.WriteLine($"Body: {responseBody}");
            Console.WriteLine("-------------------------------------\n");
        }
    }        
}
