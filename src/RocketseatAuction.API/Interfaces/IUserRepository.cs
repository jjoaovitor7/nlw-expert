using RocketseatAuction.API.Entities;

namespace RocketseatAuction.API.Interfaces;

public interface IUserRepository
{
    bool ExistUserWithEmail(string email);
    User GetUserByEmail(string email);
}