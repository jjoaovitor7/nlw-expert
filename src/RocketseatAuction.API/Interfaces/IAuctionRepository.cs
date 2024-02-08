using RocketseatAuction.API.Entities;

namespace RocketseatAuction.API.Interfaces;

public interface IAuctionRepository
{
    Auction? GetCurrent();
}