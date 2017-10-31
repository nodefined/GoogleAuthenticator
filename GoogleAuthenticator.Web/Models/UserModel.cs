using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace GoogleAuthenticator.Web.Models
{
    public class UserModel
    {
        public string UserName { get; set; }
        public string PassWord { get; set; }
        public string AccountSecretKey { get; set; }//随机码
    }
}