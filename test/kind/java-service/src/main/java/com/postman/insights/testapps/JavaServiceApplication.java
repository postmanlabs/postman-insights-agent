package com.postman.insights.testapps;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** A small HTTPS API, served by Tomcat through the JDK's SSLEngine. */
@SpringBootApplication
@RestController
public class JavaServiceApplication {
    private final AtomicLong nextOrder = new AtomicLong(1000);

    public static void main(String[] args) {
        SpringApplication.run(JavaServiceApplication.class, args);
    }

    @GetMapping("/hello")
    public Map<String, String> hello(@RequestParam(defaultValue = "world") String name) {
        return Map.of("message", "hello " + name);
    }

    @GetMapping("/orders/{id}")
    public Map<String, Object> order(@PathVariable long id) {
        Map<String, Object> order = new LinkedHashMap<>();
        order.put("id", id);
        order.put("status", "shipped");
        order.put("items", 3);
        return order;
    }

    @PostMapping("/orders")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> createOrder(@RequestBody Map<String, Object> body) {
        Map<String, Object> order = new LinkedHashMap<>(body);
        order.put("id", nextOrder.getAndIncrement());
        order.put("status", "created");
        return order;
    }
}
