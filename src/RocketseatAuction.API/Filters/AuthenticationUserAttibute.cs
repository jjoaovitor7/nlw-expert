using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using RocketseatAuction.API.Interfaces;
using RocketseatAuction.API.Services;

namespace RocketseatAuction.API.Filters;

public class AuthenticationUserAttibute : AuthorizeAttribute, IAuthorizationFilter
{
    private IUserRepository _repository;
    public AuthenticationUserAttibute(IUserRepository repository) => _repository = repository;

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        try
        {
            var token = TokenOnRequest(context.HttpContext);

            var secret = Environment.GetEnvironmentVariable("JWT_SECRET");
            var issuer = Environment.GetEnvironmentVariable("JWT_ISSUER");

            var jwtService = new JwtService(secret != null ? secret : "", issuer != null ? issuer : "");

            var data = jwtService.DecodeToken(token);

            var email = data.FindFirst(System.Security.Claims.ClaimTypes.Email);

            var exist = email != null ? _repository.ExistUserWithEmail(email.Value) : false;

            if (exist == false)
            {
                context.Result = new UnauthorizedObjectResult("E-mail not valid!");
            }
        }
        catch (Exception ex)
        {
            context.Result = new UnauthorizedObjectResult(ex.Message);
        }
    }

    private string TokenOnRequest(HttpContext context)
    {
        var authentication = context.Request.Headers.Authorization.ToString();

        if (string.IsNullOrEmpty(authentication))
        {
            throw new Exception("Token is missing.");
        }

        return authentication["Bearer ".Length..];
    }
}