using Microsoft.AspNetCore.Authorization;
using System.Diagnostics;
using AS_Assignment_2.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using AS_Assignment_2.Services;

namespace AS_Assignment_2.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryption;

        public HomeController(ApplicationDbContext context, IEncryptionService encryption)
        {
            _context = context;
            _encryption = encryption;
        }

        [HttpGet]
        public IActionResult Index()
        {
            ApplicationUser user = null;

            if (User.Identity.IsAuthenticated)
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                user = _context.Users.Find(userId);

                if (user != null)
                {
                    user.CreditCardNo = _encryption.Decrypt(user.CreditCardNo);
                }
            }

            return View(user);
        }


        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
