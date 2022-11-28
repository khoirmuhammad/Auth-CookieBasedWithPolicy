using CookieBasedAuthWithPolicy;
using CookieBasedAuthWithPolicy.Controllers;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

var myAppCors = "myAppCors";
var myAppAuthCookie = "myAppAuthCookie";

// Add services to the container.
// Configure cookie based authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(options =>
        {
            // Specify in case un-authenticated users
            options.Events.OnRedirectToLogin = (context) =>
            {
                context.Response.StatusCode = 401;
                return Task.CompletedTask;
            };

            // Specify in case authenticated users, but have no authorization (user try to access admin method)
            // By default Net Core will redirect to Account/AccessDenied. If we don't have the resource then will return 404 in our API
            options.Events.OnRedirectToAccessDenied = (context) =>
            {
                context.Response.StatusCode = 403;
                return Task.CompletedTask;
            };

            // Specify the name of the auth cookie.
            // ASP.NET picks a dumb name by default. "AspNetCore.Cookies"
            options.Cookie.Name = myAppAuthCookie;
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(AuthPolicy.ReadAuthPolicy, policy => policy.RequireRole(RoleConstant.User, RoleConstant.Admin));
    options.AddPolicy(AuthPolicy.CreateAuthPolicy, policy => policy.RequireRole(RoleConstant.Admin));
    options.AddPolicy(AuthPolicy.UpdateAuthPolicy, policy => policy.RequireClaim("IsPermanent"));
    options.AddPolicy(AuthPolicy.DeleteAuthPolicy, policy => policy.Requirements.Add(new MinimumJoinYearPolicy(10)));
});


builder.Services.AddSingleton<IAuthorizationHandler, MinimumJoinYearPolicyHandler>();

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

//app.UseCors(myAppCors);

app.UseCors(builder => builder.WithOrigins("http://localhost:4200")
        .AllowAnyMethod()
        .AllowAnyHeader()
        .AllowCredentials());

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
