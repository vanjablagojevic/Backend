﻿using System.ComponentModel.DataAnnotations;
namespace Backend.DTOs;
public class UserCreateUpdateDto
{
    [Required(ErrorMessage = "Email je obavezan.")]
    [EmailAddress(ErrorMessage = "Email nije validan.")]
    public string Email { get; set; }

    public string? Password { get; set; } 

    [Required(ErrorMessage = "Uloga je obavezna.")]
    public string Role { get; set; }

    public bool IsActive { get; set; }
}
