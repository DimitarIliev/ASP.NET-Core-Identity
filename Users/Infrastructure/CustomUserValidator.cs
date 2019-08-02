using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Users.Models;

namespace Users.Infrastructure
{
    public class CustomUserValidator : UserValidator<AppUser> //IUserValidator<AppUser>
    {
        //public Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user)
        //{
        //    if (user.Email.ToLower().EndsWith("@example.com"))
        //        return Task.FromResult(IdentityResult.Success);
        //    else
        //        return Task.FromResult(IdentityResult.Failed(new IdentityError
        //        {
        //            Code = "EmailDomainError",
        //            Description = "Only example.com email addresses are allowed"
        //        }));
        //}

        public override async Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user)
        {
            var result = await base.ValidateAsync(manager, user);

            var errors = result.Succeeded ? new List<IdentityError>() : result.Errors.ToList();

            if (!user.Email.ToLower().EndsWith("@example.com"))
                errors.Add(new IdentityError
                {
                    Code = "EmailDomainError",
                    Description = "Only example.com email addresses are allowed"
                });

            return errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed(errors.ToArray());
        }
    }
}
