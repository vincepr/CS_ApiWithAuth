using ApiWithAuth.Context;
using ApiWithAuth.Dtos;
using ApiWithAuth.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ApiWithAuth.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly UsersContext _context;
        private readonly TokenService _tokenService;
        public AuthController(UserManager<IdentityUser> userManager, UsersContext ctx, TokenService tokenService)
        {
            _userManager = userManager;
            _context = ctx;
            _tokenService = tokenService;
        }

        /*
         *  New Users Can register at this endpoint
         */
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register(RegistrationRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _userManager.CreateAsync(
                new IdentityUser { UserName = request.Username, Email = request.Email },
                request.Password
            );
            if (result.Succeeded)
            {
                request.Password = "";
                return CreatedAtAction(nameof(Register), new {email = request.Email}, request);
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(error.Code, error.Description);
            }
            return BadRequest(ModelState);
        }

        /*
         *  Existing Users can Login at this Endpoint (they receive the JWT. And then use that JWT to consume the other API endpoints that require Auth)
         */
        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<AuthResponseDto>> Authenticate([FromBody] AuthRequestDto request)
        {
            // Validate against different Fail conditions:
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var managedUser = await _userManager.FindByEmailAsync(request.Email);
            if (managedUser == null)
                return BadRequest("Bad credentials");
            var isPasswodValid = await _userManager.CheckPasswordAsync(managedUser, request.Password);
            if (!isPasswodValid)
                return BadRequest("Bad credentials");
            var userInDb = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
            if (userInDb is null || userInDb.UserName is null || userInDb.Email is null)
                return Unauthorized();

            // everything lines up -> create the actual JWT - Token
            var accessToken = _tokenService.CreateToken(userInDb);
            await _context.SaveChangesAsync();      // only if we actually created and are sending the token out, do we log it into our db.
            return Ok(new AuthResponseDto
            {
                Username = userInDb.UserName,
                Email = userInDb.Email,
                Token = accessToken,
            });
        }
    }
}
