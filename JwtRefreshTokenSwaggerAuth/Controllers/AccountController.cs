using JwtRefreshTokenSwaggerAuth.Data;
using JwtRefreshTokenSwaggerAuth.Data.Model;
using JwtRefreshTokenSwaggerAuth.Data.ModelVM;
using JwtRefreshTokenSwaggerAuth.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JwtRefreshTokenSwaggerAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly AppDbContext _db;
        private readonly PasswordHasher _passwordHasher;
        private readonly TokenService _tokenService;

        public AccountController(AppDbContext db, PasswordHasher passwordHasher, TokenService tokenService)
        {
            _db = db;
            _passwordHasher = passwordHasher;
            _tokenService = tokenService;
        }

        [HttpPost("Signup")]
        public async Task<IActionResult> Signup([FromBody] UserVM model)
        {
            var user = _db.Users.SingleOrDefault(u => u.Username == model.Username);
            if (user != null) return StatusCode(409);
            _db.Users.Add(new User
            {
                Username = model.Username,
                Password = _passwordHasher.GenerateIdentityV3Hash(model.Password)
            });
            await _db.SaveChangesAsync();
            return Ok(user);
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] UserVM model)
        {
            var user = _db.Users.SingleOrDefault(u => u.Username == model.Username);
            if (user == null || !_passwordHasher.VerifyIdentityV3Hash(model.Password, user.Password)) return BadRequest();

            var usersClaims = new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };

            var jwtToken = _tokenService.GenerateAccessToken(usersClaims);
            var refreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            await _db.SaveChangesAsync();

            return new ObjectResult(new
            {
                token = jwtToken,
                refreshToken = refreshToken
            });
        }
    }
}
