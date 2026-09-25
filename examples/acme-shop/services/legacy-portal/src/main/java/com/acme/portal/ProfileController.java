package com.acme.portal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class ProfileController {
    private final CustomerService customers;

    public ProfileController(CustomerService customers) {
        this.customers = customers;
    }

    @GetMapping("/profile")
    public String show(Model model) {
        model.addAttribute("form", new ProfileForm());
        return "profile";
    }

    @PostMapping("/profile")
    public String update(@ModelAttribute ProfileForm form, Model model) {
        customers.updateProfile(form.getEmail(), form.getDisplayName());
        model.addAttribute("saved", true);
        return "profile";
    }
}
