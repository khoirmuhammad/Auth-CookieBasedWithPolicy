using Microsoft.AspNetCore.Authorization;

namespace CookieBasedAuthWithPolicy
{
    public class MinimumJoinYearPolicy: IAuthorizationRequirement
    {
        public int MinimumJoin { get; set; }

        public MinimumJoinYearPolicy(int minimumJoin)
        {
            MinimumJoin = minimumJoin;
        }
    }
}
