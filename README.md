# Cookie Based Authentication With Policy

- Standar authentication : https://github.com/khoirmuhammad/Auth-CookieBasedStandard
- Role Based authentication : https://github.com/khoirmuhammad/Auth-CookieBasedWithRole

Here we will explain about authentication with policy. Basically Policy remains need Role mechanism and Claim as well.
- Role : likes position in organization, people's responsibility etc
- Claim : User data properties like name, age, occupation and other custom properties. It is key value combination
- Policy : Ideas that will guide our action.

### Scenario
In our application we have each of rules (I mean set of roles, claims and policies)

#### 1. Roles
- Admin & User : each of both has different responsibility

#### 2. Claims
- Basic claim : Name & Role. However for Admin has additional claims like IsPermanent & JoinDate

#### 3. Policies
- To my knowledge Policies will follow our Action Method. For instance, we have Student Controller that consists of GetStudent, PostStudent, PutStudent, DeleteStudent. So we able to create some policies like ReadStudentPolicy, CreateStudentPolicy, UpdateStudentPolicy, DeleteStudentPolicy. We able to adjust based on requirement.
- Furthermore policy will be associated to role. For instance ReadStudentPolicy can be done by Admin & User, CreateStudentPolicy, UpdateStudentPolicy, DeleteStudentPolicy can be done by Admin only etc

```
public static class RoleConstant
{
    public const string User = "User";
    public const string Admin = "Admin";
}
```
```
public static class AuthPolicy
{
    public const string ReadAuthPolicy = "ReadAuthPolicy";
    public const string CreateAuthPolicy = "CreateAuthPolicy";
    public const string UpdateAuthPolicy = "UpdateAuthPolicy";
    public const string DeleteAuthPolicy = "DeleteAuthPolicy";
}
```

```
[Authorize]
```
It means we only need user to be validated in authentication. Regardless their role

```
[Authorize(Policy = AuthPolicy.ReadAuthPolicy)]
[Authorize(Policy = AuthPolicy.CreateAuthPolicy)]
[Authorize(Policy = AuthPolicy.UpdateAuthPolicy, Roles = RoleConstant.Admin)]
[Authorize(Policy = AuthPolicy.DeleteAuthPolicy, Roles = RoleConstant.Admin)]
```

In configure Service we will see
```
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(AuthPolicy.ReadAuthPolicy, policy => policy.RequireRole(RoleConstant.User, RoleConstant.Admin));
    options.AddPolicy(AuthPolicy.CreateAuthPolicy, policy => policy.RequireRole(RoleConstant.Admin));
    options.AddPolicy(AuthPolicy.UpdateAuthPolicy, policy => policy.RequireClaim("IsPermanent"));
    options.AddPolicy(AuthPolicy.DeleteAuthPolicy, policy => policy.RequireRole(RoleConstant.Admin));
    options.AddPolicy(AuthPolicy.DeleteAuthPolicy, policy => policy.Requirements.Add(new MinimumJoinYearPolicy(10)));
});
```
Explanation :
- Read : can be done by admin and user
- Create : admin only
- Update : can be done by admin only that have permanent employee status
- Delete : custom policy, that can be done by admin only that have 10 join with company as sample

Custom Policy

```
public class MinimumJoinYearPolicy: IAuthorizationRequirement
{
    public int MinimumJoin { get; set; }

    public MinimumJoinYearPolicy(int minimumJoin)
    {
        MinimumJoin = minimumJoin;
    }
}
```
```
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
```

Dont forget to register policy handler in configure service
```
builder.Services.AddSingleton<IAuthorizationHandler, MinimumJoinYearPolicyHandler>();
```

Support reference : https://developer.okta.com/blog/2018/05/11/policy-based-authorization-in-aspnet-core

-------------------------------------------------------------------------------------------------------------------------
We try to stitching / wiring this backend service to client application. 

### Scenario
1. By default ASP.NET Core disabling CORS mechanism. It means other URL domain can't access URL of API. For instance "https://localhost:7062" is API's URL & "https://localhost:4200" is client's URL. As per cors default configuration, client app will get an error caused by cors
2. By default service will only create a cookie in same site (SameSiteMode.Unspecified). It means once we have set up the CORS policy, we able to access login process, but unable to access other resources that have [Authorize] attribute. Since, cookie doesn't create to "https://localhost:4200"

In order to solve point one, config CORS as per below code
```
app.UseCors(builder => builder.WithOrigins("http://localhost:4200")
        .AllowAnyMethod()
        .AllowAnyHeader()
        .AllowCredentials());
```

In order to deale with point two, please add the below code into cookie setting. If using Same site mode = none, don't forget to activate secure policy. We have to make sure that other URL is secure (using https instead http)
```
options.Cookie.SameSite = SameSiteMode.None;
options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
```
