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

        private List<Claim> CreateClaims(IdentityUser user)
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
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                throw;
            }
        }
        private SigningCredentials CreateSigningCredentials()
        {
            return new SigningCredentials(
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes("12354mySecredUsedToHash5678ThisMustBe256BitLongOrLonger")
                ),
                SecurityAlgorithms.HmacSha256
            );
        }
    }
}
