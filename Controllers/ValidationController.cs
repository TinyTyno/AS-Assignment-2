using AS_Assignment_2.Models;
using Microsoft.AspNetCore.Mvc;

namespace AS_Assignment_2.Controllers
{
    public class ValidationController : Controller
    {
        private readonly ApplicationDbContext _context;

        public ValidationController(ApplicationDbContext context)
        {
            _context = context;
        }

        [AcceptVerbs("GET", "POST")]
        public IActionResult IsEmailAvailable(string email)
        {
            var emailExists = _context.Users.Any(u => u.Email == email);
            return Json(!emailExists);
        }
    }
}