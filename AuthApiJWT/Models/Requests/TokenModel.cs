﻿using System.ComponentModel.DataAnnotations;

namespace AuthApiJWT.Models.Requests
{
    public class TokenModel
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
