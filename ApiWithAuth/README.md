# Dotnet API with JWT for Authentication
- https://medium.com/geekculture/how-to-add-jwt-authentication-to-an-asp-net-core-api-84e469e9f019

## imports
add the following packages:
```
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="7.0.7" />
    <PackageReference Include="Microsoft.AspNetCore.Identity.EntityFrameworkCore" Version="7.0.7" />
    <PackageReference Include="Microsoft.AspNetCore.OpenApi" Version="7.0.5" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Design" Version="7.0.7">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
    </PackageReference>
    <PackageReference Include="Npgsql.EntityFrameworkCore.PostgreSQL" Version="7.0.4" />
```

## Securing the WeatherForecast endpoint
- this will cause the API to check if a request is authorized to access this endpoint or not. 
- In our case it should check, if the user has a valid access token:

`/Controllers/WeatherForecastController.cs`
```cs
[HttpGet(Name = "GetWeatherForecast"), Microsoft.AspNetCore.Authorization.Authorize]
```

- We also have to specify the used authentication scheme of our API.
    - BEST PRACTICE: would be to move the ValidIssuer and ValidAudience strings into a configuration file like the appsettings.json
    - BEST PRACTICE: and the IssuerSigningKey should be kept in a secret place like an .env or `user secrets` or docker-secrets

`/Program.cs`
```cs
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
// specify the auth to use, and inject it to the builder:
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ClockSkew = TimeSpan.Zero,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "apiWithAuthBackend",
            ValidAudience = "apiWithAuthBackend",
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes("12354mySecredUsedToHash5678")
            ),
        };
    });

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseHttpsRedirection();
app.UseAuthorization();
// use then Authentication in the app:
app.UseAuthentication();

app.MapControllers();
app.Run();
```
- now we should get a `401` Error. Since were currently unauthorized (not using a valid JWT) to access the API.

## Connect to the docker postgresql container
- create the docker container:
    - `docker run --name auth-api-db -e POSTGRES_PASSWORD=mysecretpassword -d -p 5432:5432 postgres`
    - then stop/start it with: `docker start auth-api-db` or `docker stop auth-ap-db`

- `/Context/UsersContext.cs`
```cs
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ApiWithAuth.Context
{
    public class UsersContext : IdentityUserContext<IdentityUser>
    {
        public UsersContext(DbContextOptions<UsersContext> options)
            : base (options)
        { }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            // BEST PRACTICE wouldbe to move this out to user secrets
            optionsBuilder.UseNpgsql("Host=localhost;Database=postgres;Username=postgres;Password=mysecretpassword");
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
        }
    }
}
```
- inject the context to our Services ìn `/Program.cs`:
```cs
// inject dbcontext to our Services:
builder.Services.AddDbContext<UsersContext>();
```

## EntityFramework doing its thing
### create the db and tables with EntityFramework
```
dotnet tool install --global dotnet-ef
dotnet ef migrations add initialMigration
dotnet ef database update
```
Once finished there should be the following 5 new Tables in the database:
- `__EFMigrationsHistory`
- `AspNetUserClaims`
- `AspNetUserLogins`
- `AspNetUsers`     - Once we start registering some new users their info will get stored here.
- `AspNetUserTokens`

### Register new users
- Create a Dto for the Registration Request `/Dtos/RegistrationRequestDto.cs`
```cs
using System.ComponentModel.DataAnnotations;

namespace ApiWithAuth.Dtos
{
    public class RegistrationRequest
    {
        [Required]
        public string Email { get; set; } = null!;
        [Required]
        public string Username { get; set; } = null!;
        [Required]
        public string Password { get; set; } = null!;
    }
}
```

- Add the Controller handling the Endpoint. `/Controllers/AuthController.cs`
```cs
using ApiWithAuth.Dtos;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ApiWithAuth.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        public AuthController(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }
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
    }
}
```

Lastly Add Rules on how to IdentifyUsers and define what context to use in `/Programm.cs`
```cs
// ...
// inject our _userManager and 'connect' it with the correct db-context
builder.Services
    .AddIdentityCore<IdentityUser>(options =>
    {
        options.SignIn.RequireConfirmedAccount = false;
        options.User.RequireUniqueEmail = true;
        options.Password.RequireDigit = false;
        options.Password.RequiredLength = 6;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireLowercase = false;
    })
    .AddEntityFrameworkStores<UsersContext>();      // specify the context to the db where users information will be handled/stored
```

### Authentication logging in
- `/Services/TokenService.cs`
```cs
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace ApiWithAuth.Services
{
    // Logic Arround how to Create, Validate, Sign JWT Tokens and what Claims are used/checked against

    public class TokenService
    {
        private const int ExpirationMinutes = 30;   // how long are JWTs valid (ex. 30min then a new one needs to be requested)

        /// <summary>
        /// Create a JWT, includes info about user identity and expiration claims for the user.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public string CreateToken(IdentityUser user)
        {
            var expiration = DateTime.UtcNow.AddMinutes(ExpirationMinutes);
            var token = CreateJwt(
                    CreateClaims(user),
                    CreateSigningCredentials(),
                    expiration
            );
            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(token);
        }

        private JwtSecurityToken CreateJwt(List<Claim> claims, SigningCredentials signingCredentials, DateTime expireTime) =>
            new JwtSecurityToken(
                    "apiWithAuthBackend",
                    "apiWithAuthBackend",
                    claims,
                    expires: expireTime,
                    signingCredentials: signingCredentials
                );

        private List<Claim> CreateClaims( IdentityUser user)
        {
            try
            {
                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, "TokenForTheApiWithAuth"),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString(CultureInfo.InvariantCulture)),
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Email, user.Email),
                };
                return claims;
            } catch ( Exception ex )
            {
                Console.WriteLine(ex);
                throw;
            }
        }
        private SigningCredentials CreateSigningCredentials()
        {
            return new SigningCredentials(
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes("12354mySecredUsedToHash5678")
                ),
                SecurityAlgorithms.HmacSha256
            );
        } 
    }
}
```
- And Scope our Service into our app: `/Program.cs`
```cs
// ...
// Inject our Custom Service that creates Json-Web-Tokens (JWTs)
builder.Services.AddScoped<TokenService, TokenService>();
```
- Add the 2 Dtos `/Dtos/AuthRequestDto.cs` and `/Dtos/AuthResponseDto.cs`:
```cs
namespace ApiWithAuth.Dtos
{
    public class AuthRequestDto
    {
        public string Email { get; set; } = null!;
        public string Password { get; set; } = null!;
    }
}
```

```cs
namespace ApiWithAuth.Dtos
{
    public class AuthResponseDto
    {
        public string Username { get; set; } = null!;
        public string Email { get; set; } = null!;
        public string Token { get; set; } = null!;
    }
}
```
- Finally we add the login endpoint to our AuthController`/Controllers/AuthController`

```cs
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
            _context = ctx;
            _userManager = userManager;     // we need accesss to our _userManager
            _tokenService = tokenService;   // and our _tokenService from our freshly created Service
        }

        // ...

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
            await _context.SaveChangesAsync();      // only if we actually created and are sending the token out, do we log changes into our db.
            return Ok(new AuthResponseDto
            {
                Username = userInDb.UserName,
                Email = userInDb.Email,
                Token = accessToken,
            });
        }
    }
}
```

### Use the Token to access the weather forecast Endpoint
- in `/Programs.cs` we need to change the default line of `builder.Services.AddSwaggerGen()`
```cs
// added usings:
using Microsoft.OpenApi.Models;
// ...

```