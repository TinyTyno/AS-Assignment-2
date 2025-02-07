using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace AS_Assignment_2.Models
{
    public class UserLoginModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$",
            ErrorMessage = "Password Invalid")]
        public string Password { get; set; }

        public string RecaptchaToken { get; set; }
    }
}
