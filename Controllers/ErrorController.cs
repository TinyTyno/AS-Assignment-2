using Microsoft.AspNetCore.Diagnostics;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using AS_Assignment_2.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace AS_Assignment_2.Controllers
{
    public class ErrorController : Controller
    {
        private readonly IWebHostEnvironment _env;
        private readonly ILogger<ErrorController> _logger;

        public ErrorController(IWebHostEnvironment env, ILogger<ErrorController> logger)
        {
            _env = env;
            _logger = logger;
        }

        [Route("Error/StatusCode/{statusCode?}")]
        public IActionResult StatusCodeError(int statusCode = 404)
        {
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

            // Log the exception
            if (exception != null)
            {
                _logger.LogError(exception, "Unhandled exception occurred at {Path}",
                    exceptionHandlerPathFeature.Path);
            }

            var model = new ErrorViewModel
            {
                StatusCode = 500,
                ErrorMessage = "An unexpected error occurred.",
                ExceptionMessage = _env.IsDevelopment() ? exception?.Message : null,
                StackTrace = _env.IsDevelopment() ? exception?.StackTrace : null,
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
            };

            return View("Error", model);
        }
    }
}