﻿using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace WebApplication3.Models
{

    public class Settings
    {
        public List<RelyingParty> RelyingParties { get; set; }
    }

    public class RelyingParty
    {
        public string Metadata { get; set; }

        public string Issuer { get; set; }

        public Uri SingleSignOnDestination { get; set; }

        public Uri SingleLogoutResponseDestination { get; set; }

        public X509Certificate2 SignatureValidationCertificate { get; set; }
    }

}