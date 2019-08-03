using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Users.Models;

namespace Users.Infrastructure
{
    public class DocumentAuthorizationRequirement : IAuthorizationRequirement
    {
        public bool AllowedAuthors { get; set; }
        public bool AllowedEditors { get; set; }
    }

    public class DocumentAuthorizationHandler : AuthorizationHandler<DocumentAuthorizationRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, DocumentAuthorizationRequirement requirement)
        {
            var doc = context.Resource as ProtectedDocument;
            var user = context.User.Identity.Name;
            StringComparison compare = StringComparison.OrdinalIgnoreCase;

            if (doc != null && user != null && (requirement.AllowedAuthors && doc.Author.Equals(user, compare)) || (requirement.AllowedEditors && doc.Editor.Equals(user, compare)))
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail();
            }
            return Task.CompletedTask;
        }
    }
}
