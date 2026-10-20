package com.hdu.is.secureapi.web;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hdu.is.secureapi.dto.UserView;
import com.hdu.is.secureapi.service.UserService;

@RestController
@RequestMapping("/api")
public class DataController {

    private final UserService userService;

    public DataController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/data")
    public ResponseEntity<List<UserView>> data() {
        return ResponseEntity.ok(userService.findAll());
    }
}
