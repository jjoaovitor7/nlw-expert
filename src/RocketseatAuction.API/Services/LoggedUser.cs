using RocketseatAuction.API.Interfaces;
using RocketseatAuction.API.Entities;

namespace RocketseatAuction.API.Services;

public class LoggedUser : ILoggedUser
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IUserRepository _repository;

    public LoggedUser(IHttpContextAccessor httpContext, IUserRepository repository)
    {
        _httpContextAccessor = httpContext;
        _repository = repository;
    }

    public User User()
    {
        var secret = Environment.GetEnvironmentVariable("JWT_SECRET");
        var issuer = Environment.GetEnvironmentVariable("JWT_ISSUER");

        var jwtService = new JwtService(secret != null ? secret : "",
        issuer != null ? issuer : "");

        var token = TokenOnRequest();

        var data = jwtService.DecodeToken(token);

        var email = data.FindFirst(System.Security.Claims.ClaimTypes.Email);

        return _repository.GetUserByEmail(email != null ? email.Value : "");
    }

    private string TokenOnRequest()
    {
        var authentication = _httpContextAccessor
        .HttpContext!
        .Request
        .Headers
        .Authorization
        .ToString();

        return authentication["Bearer ".Length..];
    }
}