using RocketseatAuction.API.Entities;

namespace RocketseatAuction.API.Interfaces;

public interface IOfferRepository
{
    void Add(Offer offer);
}