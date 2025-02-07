using System;
using System.ComponentModel.DataAnnotations;

namespace AS_Assignment_2.Attributes
{
    public class EncryptedAttribute : ValidationAttribute
    {
        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            // This attribute is only a marker and does not perform validation.
            // The actual encryption will be handled elsewhere (e.g., in a service or model binder).
            return ValidationResult.Success;
        }
    }
}