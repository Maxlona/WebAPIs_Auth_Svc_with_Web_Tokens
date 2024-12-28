using System.Net;
using System.Net.Mime;
using System.Text.Json;

namespace ExceptionHandlingProject.Extensions
{
    public class ExceptionMiddleware
    {
        private readonly ILogger<ExceptionMiddleware> _logger;
        private readonly RequestDelegate _next;

        public ExceptionMiddleware(ILogger<ExceptionMiddleware> logger, RequestDelegate next)
        {
            _logger = logger;
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
                await HandleCustomExceptionResponseAsync(context, ex);
            }
        }

        private async Task HandleCustomExceptionResponseAsync(HttpContext context, Exception ex)
        {
            context.Response.ContentType = MediaTypeNames.Application.Json;
            context.Response.StatusCode = 500;

            int statusCode = 500;
            string Error = ex.Message;
            if (ex.Message.StartsWith("Account_Error: ") || ex.Message.StartsWith("Not_Found: "))
            {
                statusCode = (int)HttpStatusCode.BadRequest;
                Error = ex.Message.Replace("Account_Error: ", string.Empty).Replace("Not_Found: ", string.Empty);
            }
            ErrorModel mod = new ErrorModel()
            {
                message = Error,
                statusCode = statusCode,
            };

            context.Response.StatusCode = statusCode;
            string jsonString = JsonSerializer.Serialize(mod);
            await context.Response.WriteAsync(jsonString);
        }
    }
}