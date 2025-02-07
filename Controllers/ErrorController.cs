using Microsoft.AspNetCore.Diagnostics;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using AS_Assignment_2.Models;

namespace AS_Assignment_2.Controllers
{
    public class ErrorController : Controller
    {
        [Route("Error/StatusCode/{statusCode?}")]
        public IActionResult StatusCodeError(int statusCode = 404)
        {
            // Customize messages based on status code
            var errorMessage = statusCode switch
            {
                403 => "Access Denied. You don't have permission to view this page.",
                404 => "Page Not Found. The resource you requested does not exist.",
                500 => "Internal Server Error. Something went wrong on our end.",
                _ => "An unexpected error occurred."
            };

            var model = new ErrorViewModel
            {
                StatusCode = statusCode,
                ErrorMessage = errorMessage,
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
            };

            return View("Error", model);
        }

        [Route("Error/Exception")]
        public IActionResult ExceptionError()
        {
            var exceptionHandlerPathFeature = HttpContext.Features.Get<IExceptionHandlerPathFeature>();
            var exception = exceptionHandlerPathFeature?.Error;

            // Log the exception here (e.g., Serilog, Application Insights)

            var model = new ErrorViewModel
            {
                StatusCode = 500,
                ErrorMessage = "An unexpected error occurred.",
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
            };

            return View("Error", model);
        }
    }
}
