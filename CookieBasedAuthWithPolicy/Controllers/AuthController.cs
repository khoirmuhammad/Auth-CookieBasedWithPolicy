using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace CookieBasedAuthWithPolicy.Controllers
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public bool IsEmployeePermanent { get; set; }
        public DateTime JoinDate { get; set; }

        public List<User> GetUsers()
        {
            List<User> users = new List<User>();

            users.Add(new User
            {
                Username = "user",
                Password = "user",
                Role = RoleConstant.User,
                IsEmployeePermanent = false,
                JoinDate = new DateTime(2020,10,10)
            });

            users.Add(new User
            {
                Username = "admin1",
                Password = "admin1",
                Role = RoleConstant.Admin,
                IsEmployeePermanent = true,
                JoinDate = new DateTime(2018,12,1)
            });

            users.Add(new User
            {
                Username = "admin2",
                Password = "admin2",
                Role = RoleConstant.Admin,
                IsEmployeePermanent = true,
                JoinDate = new DateTime(2011, 5, 3)
            });

            return users;
        }
    }

    public static class RoleConstant
    {
        public const string User = "User";
        public const string Admin = "Admin";
    }

    public static class AuthPolicy
    {
        public const string ReadAuthPolicy = "ReadAuthPolicy";
        public const string CreateAuthPolicy = "CreateAuthPolicy";
        public const string UpdateAuthPolicy = "UpdateAuthPolicy";
        public const string DeleteAuthPolicy = "DeleteAuthPolicy";
    }

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login(string username, string password)
        {
            User userObj = new User();

            bool isAuth = userObj.GetUsers().Where(w => w.Username == username && w.Password == password).Any();

            if (!isAuth)
                return Unauthorized();

            var user = userObj.GetUsers().Where(w => w.Username == username && w.Password == password).First();

            var claims = new List<Claim>();

            if (user.IsEmployeePermanent)
            {
                claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Role, user.Role),
                    new Claim("IsPermanent", "1"),
                    new Claim("JoinDate", user.JoinDate.ToString())
                };
            }
            else
            {
                claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Role, user.Role)
                };
            }

            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity));

            return Ok();
        }

        [Authorize]
        [HttpPost]
        [Route("Logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Ok();
        }

        [Authorize(Policy = AuthPolicy.ReadAuthPolicy)]
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("Read Auth Policy");
        }

        [Authorize(Policy = AuthPolicy.CreateAuthPolicy)]
        [HttpPost]
        public IActionResult Post()
        {
            return Ok("Create Auth Policy");
        }

        [Authorize(Policy = AuthPolicy.UpdateAuthPolicy, Roles = RoleConstant.Admin)]
        [HttpPut]
        public IActionResult Put()
        {
            return Ok("Update Auth Policy");
        }

        [Authorize(Policy = AuthPolicy.DeleteAuthPolicy)]
        [HttpDelete]
        public IActionResult Delete()
        {
            return Ok("Delete Auth Policy");
        }
    }
}
