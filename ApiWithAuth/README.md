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

`/Dtos/RegistrationRequestDto.cs`
```cs

```

`/Controllers/AuthController.cs`
```cs

```