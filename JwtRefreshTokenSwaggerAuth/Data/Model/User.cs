using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtRefreshTokenSwaggerAuth.Data.Model
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string RefreshToken { get; set; }
    }
}
