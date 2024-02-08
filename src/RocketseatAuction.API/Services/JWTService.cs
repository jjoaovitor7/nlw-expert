using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace RocketseatAuction.API.Services;
public class JwtService
{
  private readonly string _secretKey;
  private readonly string _issuer;

  public JwtService(string secretKey, string issuer)
  {
    _secretKey = secretKey;
    _issuer = issuer;
  }

  public string GenerateToken(string userId, string role)
  {
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(_secretKey);

    var claims = new[]
    {
      new Claim(ClaimTypes.NameIdentifier, userId),
      new Claim(ClaimTypes.Role, role)
    };

    var tokenDescriptor = new SecurityTokenDescriptor
    {
      Subject = new ClaimsIdentity(claims),
      Expires = DateTime.UtcNow.AddHours(8),
      Issuer = _issuer,
      SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
  }

  public ClaimsPrincipal DecodeToken(string token)
  {
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(_secretKey);

    var tokenValidationParameters = new TokenValidationParameters
    {
      ValidateIssuerSigningKey = true,
      IssuerSigningKey = new SymmetricSecurityKey(key),
      ValidateIssuer = true,
      ValidIssuer = _issuer,
      ValidateAudience = false,
      ValidateLifetime = true
    };

    SecurityToken securityToken;
    var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);

    return principal;
  }
}