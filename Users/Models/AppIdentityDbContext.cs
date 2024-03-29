﻿using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Users.Models
{
    public class AppIdentityDbContext: IdentityDbContext<AppUser>
    {
        public AppIdentityDbContext(DbContextOptions<AppIdentityDbContext> options): base(options) { }

        public static async Task CreateAdminAccount(IServiceProvider serviceProvider,
            IConfiguration configuration)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var userManager = (UserManager<AppUser>)scope.ServiceProvider.GetService(typeof(UserManager<AppUser>));
                var roleManager = (RoleManager<IdentityRole>)scope.ServiceProvider.GetService(typeof(RoleManager<IdentityRole>));

                var userName = configuration["Data:AdminUser:Name"];
                var email = configuration["Data:AdminUser:Email"];
                var password = configuration["Data:AdminUser:Password"];
                var role = configuration["Data:AdminUser:Role"];

                if (await userManager.FindByNameAsync(userName) == null)
                {
                    if (await roleManager.FindByNameAsync(role) == null)
                    {
                        await roleManager.CreateAsync(new IdentityRole(role));
                    }
                }

                var user = new AppUser
                {
                    UserName = userName,
                    Email = email
                };

                var result = await userManager.CreateAsync(user, password);

                if (result.Succeeded)
                    await userManager.AddToRoleAsync(user, role);
            }          
        }
    }
}
