using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Users.Models
{
    public enum Cities
    {
        None, London, Paris, Chicago
    }

    public enum QualificationLevels
    {
        None, Basic, Advanced
    }

    public class AppUser: IdentityUser
    {
        //no additional members are required
        //for basic Identity installation

        public Cities City { get; set; }
        public QualificationLevels Qualifications { get; set; }
    }
}
