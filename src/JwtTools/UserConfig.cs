using System;
using System.Collections.Generic;
using System.Text;

namespace DotnetJwtTools
{
    public class UserConfig
    {
        //public string ValidationAuthUrl { get; set; }
        //public string ValidationPublicKey { get; set; }
        public string ClaimUrl { get; set; }
        public string ClaimIam { get; set; }
        public string ClaimMemberId { get; set; }

        public UserConfig (string pClaimUrl, string pClaimIam, string pClaimMemberId)
        {
            //this.ValidationAuthUrl = pAuthUrl;
            //this.ValidationPublicKey = pCertificate;
            this.ClaimUrl = pClaimUrl;
            this.ClaimIam = pClaimIam;
            this.ClaimMemberId = pClaimMemberId;
        }
    }
}
