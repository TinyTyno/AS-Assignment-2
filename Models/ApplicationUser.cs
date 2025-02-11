using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using AS_Assignment_2.Attributes;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace AS_Assignment_2.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required(ErrorMessage = "First Name is required")]
        [SanitizeInput]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "Last Name is required")]
        [SanitizeInput]
        public string LastName { get; set; }

        [Required(ErrorMessage = "Credit Card No is required")]
        [Encrypted]
        [ProtectedPersonalData]
        [RegularExpression(
          @"^(?:4\d{12}(?:\d{3})?|(?:5[1-5]\d{2}|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)\d{12})$",
          ErrorMessage = "Invalid Visa/Mastercard number")]
        public string CreditCardNo { get; set; }

        [Required(ErrorMessage = "Mobile No is required")]
        [RegularExpression(@"^(\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}$",
            ErrorMessage = "Invalid Singapore number (e.g. +65 8123 4567)")]
        public string MobileNo { get; set; }

        [Required(ErrorMessage = "Billing Address is required")]
        public string BillingAddress { get; set; }

        [Required(ErrorMessage = "Shipping Address is required")]
        public string ShippingAddress { get; set; }

        [NotMapped]
        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$",
            ErrorMessage = "Password must be at least 12 characters with upper, lower, number, and special")]
        public string Password { get; set; }

        [NotMapped]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; }

        [NotMapped]
        [Required(ErrorMessage = "Photo is required")]
        [ValidateFile(MaxSize = 5 * 1024 * 1024)]
        public IFormFile Photo { get; set; }

        public string? PhotoPath { get; set; }

        [ProtectedPersonalData]
        public DateTime LastPasswordChangeDate { get; set; } = DateTime.Now;

        public string PreviousPasswords { get; set; } = "[]";

        public bool PasswordChangeRequired { get; set; }

        public string? CurrentSessionId { get; set; }
    }

    public static class CreditCardHelper
    {
        public static string MaskCreditCardNumber(string creditCardNumber)
        {
            if (string.IsNullOrEmpty(creditCardNumber) || creditCardNumber.Length < 4)
            {
                return creditCardNumber; // Return as is if it's null or too short
            }

            // Mask all but the last 4 digits
            return new string('*', creditCardNumber.Length - 4) + creditCardNumber.Substring(creditCardNumber.Length - 4);
        }
    }
}