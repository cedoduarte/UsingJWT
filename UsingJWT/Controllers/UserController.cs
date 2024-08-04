using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using UsingJWT.DTOs;
using UsingJWT.Models;

namespace UsingJWT.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : Controller
    {
        private readonly IConfiguration _configuration;

        private List<User> _users = new()
        {
            new User 
            {
                Email = "carlosduarte.1@hotmail.com",
                Password = "12345"
            },
            new User 
            {
                Email = "luisdiego@hotmail.com",
                Password = "12345"
            }
        };

        public UserController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [Authorize]
        [HttpGet("get-users-with-authorization")]
        public async Task<IActionResult> GetUsersWithAuthorization()
        {
            return Ok(_users);
        }

        [HttpGet("get-users")]
        public async Task<IActionResult> GetUsers()
        {
            return Ok(_users);
        }

        [HttpPost("login")]
        public async Task<IActionResult> LogIn([FromBody] LogInDto loginDto)
        {
            
            var existingUser = _users
                .Where(u => u.Email == loginDto.Email && u.Password == loginDto.Password)
                .FirstOrDefault();
            if (existingUser is null)
            {
                return BadRequest("The user does not exist!");
            }

            var claims = new Claim[] 
            {
                new Claim(JwtRegisteredClaimNames.Sub, _configuration["Jwt:Subject"]!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("Email", loginDto.Email!)
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                _configuration["Jwt:Issuer"]!, 
                _configuration["Jwt:Audience"]!,
                claims,
                expires: DateTime.UtcNow.AddMinutes(60),
                signingCredentials: signIn);
            string tokenValue = new JwtSecurityTokenHandler().WriteToken(token);
            return Ok(new { Token = tokenValue, User = existingUser });
        }
    }
}
