using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using MeuLogin.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MeuLogin.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Index([FromQuery] string returnUrl)
        {
            Console.Write(returnUrl);
            TempData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(int id, [Bind("Email,Password")] UserModel model)
        {
            if (!ModelState.IsValid)
                return View();


            var scheme = CookieAuthenticationDefaults.AuthenticationScheme;
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "andre@balta.io"),
                new Claim(ClaimTypes.Role, "admin")
            };

            var claimsIdentity = new ClaimsIdentity(claims, scheme);

            var properties = new AuthenticationProperties
            {
                IsPersistent = true,
            };

            await HttpContext.SignInAsync(scheme, new ClaimsPrincipal(claimsIdentity), properties);

            string returnUrl = TempData["ReturnUrl"]?.ToString();
            if (!String.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                return Redirect(returnUrl);
            else
                return RedirectToAction("Index", "Home");

        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult LoginMicrosoft()
        {
            var properties = new AuthenticationProperties { RedirectUri = "ExternalLoginCallback" };
            return Challenge(properties, "Microsoft");

        }

        [AllowAnonymous]
        [HttpGet(nameof(ExternalLoginCallback))]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            var result = await HttpContext.AuthenticateAsync("Microsoft");
            if (result.Succeeded)
            {
                var token = result.Properties.Items.FirstOrDefault(x => x.Key.Contains(".Token.access_token"));
                var email = result.Principal.Claims.FirstOrDefault(x => x.Type.Contains("emailaddress")).Value;

                var scheme = CookieAuthenticationDefaults.AuthenticationScheme;
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, email),
                    new Claim(ClaimTypes.Role, "admin"),
                };

                var claimsIdentity = new ClaimsIdentity(claims, scheme);

                var properties = new AuthenticationProperties
                {
                    IsPersistent = true,
                };

                await HttpContext.SignInAsync(scheme, new ClaimsPrincipal(claimsIdentity), properties);
                Console.WriteLine(email);
            }
            return RedirectToAction("Index", "Home");
        }
    }
}