using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;
using System.IO;

public class ValidateFileAttribute : ValidationAttribute
{
    public long MaxSize { get; set; } = 5 * 1024 * 1024; // 5MB max
    private readonly string _allowedExtension = ".jpg"; // Only allow JPG

    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        if (value is IFormFile file)
        {
            // Validate file size
            if (file.Length > MaxSize)
                return new ValidationResult($"File size exceeds {MaxSize / 1024 / 1024}MB");

            // Validate file extension (must be .jpg)
            var extension = Path.GetExtension(file.FileName).ToLower();
            if (extension != _allowedExtension)
                return new ValidationResult("Only JPG files are allowed.");
        }
        return ValidationResult.Success;
    }
}
