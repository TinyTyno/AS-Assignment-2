using System.Security.Claims;
using AS_Assignment_2.Models;
using AS_Assignment_2.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using AS_Assignment_2.Models.AS_Assignment_2.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Newtonsoft.Json;
using Ganss.Xss;


namespace AS_Assignment_2.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryption;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RecaptchaService _recaptchaService;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;
        private readonly HtmlSanitizer _sanitizer = new HtmlSanitizer();



        public AccountController(
            ApplicationDbContext context,
            IEncryptionService encryption,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RecaptchaService recaptchaService,
            IEmailService emailService,
            IConfiguration configuration)
        {
            _context = context;
            _encryption = encryption;
            _userManager = userManager;
            _signInManager = signInManager;
            _recaptchaService = recaptchaService;
            _emailService = emailService;
            _configuration = configuration;
        }

        [HttpGet]
        public IActionResult Register()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                HttpContext.Session.Clear();
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(ApplicationUser model)
        {
            if (ModelState.IsValid)
            {
                // Check if email already exists
                var existingUser = await _userManager.FindByEmailAsync(model.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError("Email", "This email address is already registered.");
                    return View(model);
                }

                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    CreditCardNo = _encryption.Encrypt(model.CreditCardNo),
                    MobileNo = model.MobileNo,
                    BillingAddress = _sanitizer.Sanitize(model.BillingAddress),
                    ShippingAddress = _sanitizer.Sanitize(model.ShippingAddress),
                    PhotoPath = model.Photo != null ? await SavePhoto(model.Photo) : null,
                    LastPasswordChangeDate = DateTime.UtcNow,
                };
                model.Password = _sanitizer.Sanitize(model.Password);
                var passwordHash = _userManager.PasswordHasher.HashPassword(user, model.Password);
                user.PreviousPasswords = JsonConvert.SerializeObject(new List<string> { passwordHash });
                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    await LogActivity(user.Id, "Registration");
                    return RedirectToAction("Login");
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }
            return View(model);
        }

        [HttpGet]
        public IActionResult Login()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                HttpContext.Session.Clear();
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(UserLoginModel model, string recaptchaToken)
        {
            if (!await _recaptchaService.VerifyReCaptchaV3(recaptchaToken))
            {
                ModelState.AddModelError("", "reCAPTCHA verification failed");
                return View(model);
            }

            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    ModelState.AddModelError("", "Invalid credentials");
                    return View(model);
                }

                if (await _userManager.IsLockedOutAsync(user))
                {
                    ModelState.AddModelError("", $"Account locked. Try again in a while");
                    return View(model);
                }

                model.Password = _sanitizer.Sanitize(model.Password);
                var isPasswordValid = await _userManager.CheckPasswordAsync(user, model.Password);
                Console.WriteLine("Check Password");
                if (isPasswordValid)
                {
                    Console.WriteLine("Password Valid");
                    // Reset failed attempts on successful password check
                    await _userManager.ResetAccessFailedCountAsync(user);

                    // Generate and send OTP
                    var otpCode = GenerateOtp();
                    await _emailService.SendOtpEmailAsync(user.Email, otpCode);
                    await StoreOtp(user.Id, otpCode);

                    // Store 2FA state in session
                    HttpContext.Session.SetString("2faUserId", user.Id);
                    HttpContext.Session.SetString("2faPending", "true");

                    HttpContext.Session.SetInt32("OtpAttempts", 0);

                    return RedirectToAction("VerifyOtp");
                }
                else
                {
                    Console.WriteLine("Password Invalid");
                    // Increment failed attempts
                    await _userManager.AccessFailedAsync(user);

                    // Check if locked out after incrementing
                    if (await _userManager.IsLockedOutAsync(user))
                    {
                        Console.WriteLine("Account locked");
                        ModelState.AddModelError("", $"Account locked. Try again in {_configuration["PasswordPolicy:AccountLockoutTimeSpanMinutes"]} minutes");
                    }
                    else
                    {
                        Console.WriteLine("Account not locked");
                        ModelState.AddModelError("", "Invalid credentials");
                    }

                    return View(model);
                }
            }
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> VerifyOtp()
        {
            var userId = HttpContext.Session.GetString("2faUserId");
            if (userId == null)
            {
                return RedirectToAction("Login");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            ViewBag.Email = user.Email;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyOtp(string otpCode)
        {
            otpCode = _sanitizer.Sanitize(otpCode);
            var userId = HttpContext.Session.GetString("2faUserId");
            var is2faPending = HttpContext.Session.GetString("2faPending") == "true";
            if (userId == null || !is2faPending)
            {
                return RedirectToAction("Login");
            }

            var attempts = HttpContext.Session.GetInt32("OtpAttempts") ?? 0;

            // Enforce maximum attempts
            if (attempts >= 3)
            {
                await ClearOtpAndSession(userId);
                ModelState.AddModelError("", "Maximum OTP attempts exceeded. Please login again.");
                return RedirectToAction("Login");
            }

            var isValid = await ValidateOtp(userId, otpCode);
            if (isValid)
            {
                HttpContext.Session.Remove("OtpAttempts");

                var user = await _userManager.FindByIdAsync(userId);

                // Generate new session ID
                var newSessionId = Guid.NewGuid().ToString();
                user.CurrentSessionId = newSessionId;
                await _userManager.UpdateAsync(user);

                // Store in current session
                HttpContext.Session.SetString("CurrentSessionId", newSessionId);

                // Check password age
                var maxPasswordAge = TimeSpan.FromDays(Double.Parse(_configuration["PasswordPolicy:MaximumAge"]));
                Console.WriteLine($"Age of password: {DateTime.UtcNow - user.LastPasswordChangeDate}");
                if (DateTime.UtcNow - user.LastPasswordChangeDate > maxPasswordAge)
                {
                    // Force password change
                    user.PasswordChangeRequired = true;
                    await _userManager.UpdateAsync(user);

                    // Store user ID in session for password change flow
                    HttpContext.Session.SetString("ForcePasswordChangeUserId", userId);
                    HttpContext.Session.SetString("ForcePasswordChange", "true");

                    return RedirectToAction("ForceChangePassword");
                }
                else
                {
                    await _signInManager.SignInAsync(user, false);

                    // Clear 2FA state
                    HttpContext.Session.Remove("2faUserId");
                    HttpContext.Session.Remove("2faPending");

                    await LogActivity(user.Id, "Login");
                    return RedirectToAction("Index", "Home");
                }
            }
            else
            {
                attempts++;

                if (attempts >= 3)
                {
                    await ClearOtpAndSession(userId);
                    ModelState.AddModelError("", "Maximum OTP attempts exceeded. Please login again.");
                    return RedirectToAction("Login");
                }

                HttpContext.Session.SetInt32("OtpAttempts", attempts);
                ModelState.AddModelError("", $"Invalid OTP. {3 - attempts} attempt(s) remaining.");
            }

            ModelState.AddModelError("", "Invalid or expired OTP code");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResendOtp()
        {
            var userId = HttpContext.Session.GetString("2faUserId");
            if (userId == null) return RedirectToAction("Login");

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return RedirectToAction("Login");

            // Check if cooldown period has elapsed
            var lastSentTime = HttpContext.Session.GetString("LastOtpSentTime");
            if (lastSentTime != null)
            {
                var lastSentDateTime = DateTime.Parse(lastSentTime);
                if (DateTime.UtcNow < lastSentDateTime.AddMinutes(5))
                {
                    // Cooldown period has not elapsed
                    TempData["Message"] = "Please wait before requesting a new OTP.";
                    return RedirectToAction("VerifyOtp");
                }
            }

            // Generate a new OTP
            var newOtp = GenerateOtp();
            await StoreOtp(user.Id, newOtp);
            await _emailService.SendOtpEmailAsync(user.Email, newOtp);

            HttpContext.Session.SetInt32("OtpAttempts", 0);

            // Update the last sent time in the session
            HttpContext.Session.SetString("LastOtpSentTime", DateTime.UtcNow.ToString());

            TempData["Message"] = "A new OTP has been sent to your email.";
            return RedirectToAction("VerifyOtp");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId != null)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    user.CurrentSessionId = null;
                    await _userManager.UpdateAsync(user);
                }
                await LogActivity(userId, "Logout");
            }

            await HttpContext.SignOutAsync("Identity.Application");
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        [HttpGet]
        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            model.Email = _sanitizer.Sanitize(model.Email);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action("ResetPasswordConfirm", "Account",
                    new { email = user.Email, token }, protocol: HttpContext.Request.Scheme);

                await _emailService.SendPasswordResetEmailAsync(user.Email, callbackUrl);
            }

            // Always return confirmation to prevent email enumeration
            return View("ResetPasswordConfirmMsg");
        }

        [HttpGet]
        public IActionResult ResetPasswordConfirm(string email, string token)
        {
            // Add error handling for invalid tokens
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                return RedirectToAction("ResetPassword");
            }

            var user = _userManager.FindByEmailAsync(email).Result;
            if (user == null || !_userManager.VerifyUserTokenAsync(user,
                TokenOptions.DefaultProvider,
                "ResetPassword",
                token).Result)
            {
                ModelState.AddModelError("", "Invalid password reset token");
                return RedirectToAction("ResetPassword");
            }

            // Preserve parameters in the view
            return View(new ResetPasswordConfirmModel
            {
                Email = email,
                Token = token
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPasswordConfirm(ResetPasswordConfirmModel model)
        {
            model.Email = _sanitizer.Sanitize(model.Email);
            model.Token = _sanitizer.Sanitize(model.Token);
            model.NewPassword = _sanitizer.Sanitize(model.NewPassword);
            model.ConfirmPassword = _sanitizer.Sanitize(model.ConfirmPassword);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid password reset request");
                return View(model);
            }

            // Check 1: Ensure last password change was more than x day ago
            if (user.LastPasswordChangeDate.AddDays(Double.Parse(_configuration["PasswordPolicy:MinimumAge"])) > DateTime.UtcNow)
            {
                ModelState.AddModelError("", "You cannot reset your password within 24 hours of the last change.");
                return View(model);
            }


            // Check 2: Ensure new password is not in previous passwords
            var existingPasswords = JsonConvert.DeserializeObject<List<string>>(user.PreviousPasswords ?? "[]");
            foreach (var oldHash in existingPasswords)
            {
                if (_userManager.PasswordHasher.VerifyHashedPassword(user, oldHash, model.NewPassword)
                    == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError("", "Cannot reuse previous passwords");
                    return View(model);
                }
            }



            // Proceed with password reset if checks pass
            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (result.Succeeded)
            {
                // Update password history
                var newHash = _userManager.PasswordHasher.HashPassword(user, model.NewPassword);
                existingPasswords.Add(newHash);
                if (existingPasswords.Count > Double.Parse(_configuration["PasswordPolicy:PasswordHistory"])) existingPasswords.RemoveAt(0);
                user.PreviousPasswords = JsonConvert.SerializeObject(existingPasswords);
                user.LastPasswordChangeDate = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);


                await HttpContext.SignOutAsync("Identity.Application");
                HttpContext.Session.Clear();

                await LogActivity(user.Id, "Update password");
                return RedirectToAction("ResetPasswordSuccess");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            return View(model);
        }

        [HttpGet]
        public IActionResult ResetPasswordSuccess()
        {
            Console.WriteLine("YAY!!!");
            return View();
        }

        [HttpGet]
        public IActionResult ForceChangePassword()
        {
            var userId = HttpContext.Session.GetString("ForcePasswordChangeUserId");
            if (userId == null)
            {
                return RedirectToAction("Login");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForceChangePassword(ForceChangePasswordModel model)
        {
            model.NewPassword = _sanitizer.Sanitize(model.NewPassword);
            model.ConfirmPassword = _sanitizer.Sanitize(model.ConfirmPassword);

            var userId = HttpContext.Session.GetString("ForcePasswordChangeUserId");
            if (userId == null) return RedirectToAction("Login");

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return RedirectToAction("Login");

            // Check 1: Ensure last password change was more than x day ago
            if (user.LastPasswordChangeDate.AddDays(Double.Parse(_configuration["PasswordPolicy:MinimumAge"])) > DateTime.UtcNow)
            {
                ModelState.AddModelError("", "You cannot reset your password within 24 hours of the last change.");
                return View(model);
            }

            // Check 2: Ensure new password is not in previous passwords
            var existingPasswords = JsonConvert.DeserializeObject<List<string>>(user.PreviousPasswords ?? "[]");
            foreach (var oldHash in existingPasswords)
            {
                if (_userManager.PasswordHasher.VerifyHashedPassword(user, oldHash, model.NewPassword)
                    == PasswordVerificationResult.Success)
                {
                    ModelState.AddModelError("", "Cannot reuse previous passwords");
                    return View(model);
                }
            }

            var result = await _userManager.ResetPasswordAsync(
                user,
                await _userManager.GeneratePasswordResetTokenAsync(user),
                model.NewPassword
            );

            if (result.Succeeded)
            {
                await LogActivity(user.Id, "Update password");

                // Generate new session ID
                var newSessionId = Guid.NewGuid().ToString();
                user.CurrentSessionId = newSessionId;
                await _userManager.UpdateAsync(user);

                // Store in current session
                HttpContext.Session.SetString("CurrentSessionId", newSessionId);

                // Clear force password change session variables
                HttpContext.Session.Remove("ForcePasswordChangeUserId");
                HttpContext.Session.Remove("ForcePasswordChange");

                // Clear 2FA session variables
                HttpContext.Session.Remove("2faUserId");
                HttpContext.Session.Remove("2faPending");

                user.LastPasswordChangeDate = DateTime.UtcNow;
                user.PasswordChangeRequired = false;
                await _userManager.UpdateAsync(user);

                // Sign in the user
                await _signInManager.SignInAsync(user, false);
                return RedirectToAction("Index", "Home");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            return View();
        }

        private async Task<string> SavePhoto(IFormFile photo)
        {
            var uploads = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/uploads");
            Directory.CreateDirectory(uploads);

            var fileName = $"{Guid.NewGuid()}{Path.GetExtension(photo.FileName)}";
            var filePath = Path.Combine(uploads, fileName);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await photo.CopyToAsync(stream);
            }

            return $"/uploads/{fileName}";
        }

        private async Task LogActivity(string userId, string activity)
        {
            try
            {
                _context.AuditLogs.Add(new AuditLog
                {
                    UserId = userId,
                    Activity = activity,
                    Timestamp = DateTime.UtcNow,
                    Details = $"IP: {HttpContext.Connection.RemoteIpAddress}"
                });
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                // Log or handle the error appropriately
                Console.WriteLine($"Error logging activity: {ex.Message}");
            }
        }

        private string GenerateOtp()
        {
            var rng = new Random();
            return rng.Next(100000, 999999).ToString();
        }

        private async Task StoreOtp(string userId, string code)
        {
            await _context.Otps.AddAsync(new Otp
            {
                UserId = userId,
                Code = code,
                Expiry = DateTime.UtcNow.AddMinutes(5)
            });
            await _context.SaveChangesAsync();
        }

        private async Task<bool> ValidateOtp(string userId, string code)
        {
            var otp = await _context.Otps
                .Where(o => o.UserId == userId && o.Code == code && o.Expiry > DateTime.UtcNow)
                .FirstOrDefaultAsync();

            if (otp != null)
            {
                _context.Otps.Remove(otp);
                await _context.SaveChangesAsync();
                return true;
            }
            return false;
        }

        private async Task ClearOtpAndSession(string userId)
        {
            var existingOtps = await _context.Otps.Where(o => o.UserId == userId).ToListAsync();
            _context.Otps.RemoveRange(existingOtps);
            await _context.SaveChangesAsync();

            HttpContext.Session.Remove("2faUserId");
            HttpContext.Session.Remove("2faPending");
            HttpContext.Session.Remove("OtpAttempts");
        }
    }
}