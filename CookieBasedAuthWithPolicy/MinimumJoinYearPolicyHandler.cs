using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace CookieBasedAuthWithPolicy
{
    public class MinimumJoinYearPolicyHandler : AuthorizationHandler<MinimumJoinYearPolicy>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MinimumJoinYearPolicy requirement)
        {
            if (!context.User.HasClaim(c => c.Type == "JoinDate"))
            {
                return Task.CompletedTask;
            }

            var joinDate = Convert.ToDateTime(context.User.FindFirst(c => c.Type == "JoinDate")?.Value);

            var userAge = DateTime.Today.Year - joinDate.Year;

            if (joinDate > DateTime.Today.AddYears(-userAge))
            {
                userAge--;
            }

            if (userAge >= requirement.MinimumJoin)
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }
    }
}
