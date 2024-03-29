﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Users.Models;

namespace Users.Controllers
{
    public class HomeController : Controller
    {
        private UserManager<AppUser> userManager;
        //[Authorize]
        //public ViewResult Index() => View(new Dictionary<string, object> { ["Placeholder"] = "Placeholder" });

        public HomeController(UserManager<AppUser> userMgr)
        {
            userManager = userMgr;
        }

        [Authorize]
        public IActionResult Index() => View(GetData(nameof(Index)));

        //[Authorize(Roles = "Users")]
        [Authorize(Policy = "DCUsers")]
        public IActionResult OtherAction() => View("Index", GetData(nameof(OtherAction)));

        private Dictionary<string, object> GetData(string actionName) =>
            new Dictionary<string, object>
            {
                ["Action"] = actionName,
                ["User"] = HttpContext.User.Identity.Name,
                ["Authenticated"] = HttpContext.User.Identity.IsAuthenticated,
                ["Auth Type"] = HttpContext.User.Identity.AuthenticationType,
                ["In Users Role"] = HttpContext.User.IsInRole("Users"),
                ["City"] = CurrentUser.Result.City,
                ["Qualification"] = CurrentUser.Result.Qualifications
            };

        [Authorize]
        public async Task<IActionResult> UserProps() => View(await CurrentUser);

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> UserProps([Required]Cities city, [Required]QualificationLevels qualifications)
        {
            if (ModelState.IsValid)
            {
                var user = await CurrentUser;
                user.City = city;
                user.Qualifications = qualifications;
                await userManager.UpdateAsync(user);
                return RedirectToAction("Index");
            }
            return View(await CurrentUser);
        }

        private Task<AppUser> CurrentUser => userManager.FindByNameAsync(HttpContext.User.Identity.Name);

        [Authorize(Policy = "NotBob")]
        public IActionResult NotBob() => View("Index", GetData(nameof(NotBob)));
    }
}
