using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using ProductsApi.Models;
using ProductsApi.Services;

namespace ProductsApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[AllowAnonymous]
public class AuthController : ControllerBase
{
    private readonly JwtTokenService _jwtTokenService;
    private readonly IConfiguration _configuration;

    public AuthController(JwtTokenService jwtTokenService, IConfiguration configuration)
    {
        _jwtTokenService = jwtTokenService;
        _configuration = configuration;
    }

    [HttpPost("login")]
    [EnableRateLimiting("auth")]
    public ActionResult<LoginResponse> Login([FromBody] LoginRequest request)
    {
        var expectedUsername = _configuration["Auth:Username"];
        var expectedPassword = _configuration["Auth:Password"];

        if (string.IsNullOrEmpty(expectedUsername) || string.IsNullOrEmpty(expectedPassword))
        {
            return StatusCode(StatusCodes.Status500InternalServerError, "Auth credentials are not configured.");
        }

        if (request.Username != expectedUsername || request.Password != expectedPassword)
        {
            return Unauthorized(new { message = "Invalid username or password." });
        }

        var (token, expiresAt) = _jwtTokenService.CreateToken(request.Username);

        return Ok(new LoginResponse
        {
            Token = token,
            ExpiresAt = expiresAt
        });
    }
}
