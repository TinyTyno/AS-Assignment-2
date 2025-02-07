using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;
using System.Reflection;

public class SanitizeInputAttribute : ValidationAttribute
{
    protected override ValidationResult IsValid(object value, ValidationContext context)
    {
        if (value is string input)
        {
            // Encode input to prevent XSS
            var sanitized = HtmlEncoder.Default.Encode(input);

            // Set sanitized value back to the property
            PropertyInfo property = context.ObjectInstance.GetType().GetProperty(context.MemberName);
            if (property != null && property.CanWrite)
            {
                property.SetValue(context.ObjectInstance, sanitized);
            }
        }
        return ValidationResult.Success;
    }
}
