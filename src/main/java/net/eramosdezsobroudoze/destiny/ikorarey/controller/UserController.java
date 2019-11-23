package net.eramosdezsobroudoze.destiny.ikorarey.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController("/user")
public class UserController {

    @GetMapping(
        value = "/user"
        , produces = {MediaType.APPLICATION_JSON_VALUE}
    )
    public Principal user(Principal principal) {
        return principal;
    }
}
