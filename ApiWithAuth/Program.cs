using ApiWithAuth.Context;
using ApiWithAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;


var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// get our Configuration-Connection String:
var conn = builder.Configuration.GetConnectionString("ApiWithAuthDbConnStr");
// inject dbcontext to our Services:
builder.Services.AddDbContext<UsersContext>(options => options.UseSqlServer(conn));

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
                Encoding.UTF8.GetBytes("12354mySecredUsedToHash5678ThisMustBe256BitLongOrLonger")       // this should obviously be in a save location secret/ .env etc...
            ),
        };
    });

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

// Inject our Custom Service that creates Json-Web-Tokens (JWTs)
builder.Services.AddScoped<TokenService, TokenService>();

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
