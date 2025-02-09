using AS_Assignment_2.Services;
using Microsoft.EntityFrameworkCore;
using AS_Assignment_2.Models;
using Microsoft.AspNetCore.Identity;
using AS_Assignment_2.Models.AS_Assignment_2.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Builder;
using AS_Assignment_2.Controllers;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString")));

// Add Identity services
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(
        builder.Configuration.GetValue<double>("PasswordPolicy:AccountLockoutTimeSpanMinutes")
    );
    options.Lockout.MaxFailedAccessAttempts = builder.Configuration.GetValue<int>("PasswordPolicy:MaxFailedAccessAttempts");
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Add password policy configuration
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 12;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.User.RequireUniqueEmail = true;
});

// Add cookie configuration
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
    options.SlidingExpiration = true;
    options.Cookie.HttpOnly = true;
});

builder.Services.AddScoped<IPasswordHasher, BCryptPasswordHasher>();
builder.Services.AddScoped<IEncryptionService, AesEncryptionService>();
builder.Services.AddHttpClient<RecaptchaService>();

builder.Services.AddDistributedMemoryCache();

// Add session configuration
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(
        builder.Configuration.GetValue<double>("SessionPolicy:SessionTimeout")
    );
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;  
});

// Add email service configuration
builder.Services.Configure<SendGridSettings>(
    builder.Configuration.GetSection("SendGridSettings"));
builder.Services.AddScoped<IEmailService, SendGridEmailService>();

// Add 2FA configuration
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});

var app = builder.Build();

// Error handling middleware
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error/Exception");
    app.UseHsts();
}
else
{
    app.UseDeveloperExceptionPage();
}

// Handle HTTP status codes
app.UseStatusCodePagesWithReExecute("/Error/StatusCode/{0}");

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

// Middleware to add security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    await next();
});

// Force password change middleware
app.Use(async (context, next) =>
{
    var path = context.Request.Path;
    var session = context.Session;

    // Redirect to password change if session exists and not already on the page
    if (!path.StartsWithSegments("/Account/ForceChangePassword") &&
        session.TryGetValue("ForcePasswordChangeUserId", out _))
    {
        context.Response.Redirect("/Account/ForceChangePassword");
        return;
    }

    await next();
});

// Middleware to check 2FA Completion
app.Use(async (context, next) =>
{
    var path = context.Request.Path;
    if (context.User.Identity.IsAuthenticated &&
        !path.StartsWithSegments("/Account/VerifyOtp") &&
        !path.StartsWithSegments("/Account/Logout"))
    {
        var session = context.Session;
        var is2faPending = session.GetString("2faPending") == "true";

        if (is2faPending)
        {
            // Use correct scheme name
            await context.SignOutAsync("Identity.Application");
            session.Clear();
            context.Response.Redirect("/Account/Login");
            return;
        }
    }
    await next();
});

app.Use(async (context, next) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        var userManager = context.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.GetUserAsync(context.User);

        var currentSessionId = context.Session.GetString("CurrentSessionId");

        if (user == null || user.CurrentSessionId != currentSessionId)
        {
            // Invalidate the current session
            await context.SignOutAsync("Identity.Application");
            context.Session.Clear();
            context.Response.Redirect("/Account/Login");
            return;
        }
    }

    await next();
});

app.Use(async (context, next) =>
{
    var path = context.Request.Path;
    if (path.StartsWithSegments("/Account/VerifyOtp") &&
        !context.Session.TryGetValue("2faPending", out _))
    {
        context.Response.Redirect("/Account/Login");
        return;
    }
    await next();
});

app.Use(async (context, next) =>
{
    if (context.User.Identity.IsAuthenticated)
    {
        var userManager = context.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.GetUserAsync(context.User);

        if (user?.PasswordChangeRequired == true)
        {
            context.Response.Redirect("/Account/ForceChangePassword");
            return;
        }
    }
    await next();
});

app.Use(async (context, next) =>
{
    var path = context.Request.Path;
    var authPaths = new[] { "/Account/Login", "/Account/Register", "/Account/ResetPassword" };

    if (context.User.Identity.IsAuthenticated && authPaths.Any(p => path.StartsWithSegments(p)))
    {
        context.Response.Redirect("/Home/Index");
        return;
    }
    await next();
});


app.Use(async (context, next) =>
{
    var path = context.Request.Path;

    // Updated session key check
    if (path.StartsWithSegments("/Account/ForceChangePassword") &&
        !context.Session.TryGetValue("ForcePasswordChangeUserId", out _))
    {
        context.Response.Redirect("/Account/Login");
        return;
    }

    // Keep existing ResetPasswordConfirm checks
    if (path.StartsWithSegments("/Account/ResetPasswordConfirm"))
    {
        if (string.IsNullOrEmpty(context.Request.Query["token"]) ||
            string.IsNullOrEmpty(context.Request.Query["email"]))
        {
            context.Response.Redirect("/Account/ResetPassword");
            return;
        }
    }

    await next();
});

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapFallbackToController("StatusCodeError", "Error", "{*path}");


app.Run();