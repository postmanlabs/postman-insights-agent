// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.testdata;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Phase 5c.2 Tomcat HTTPS workload — Spring Boot with the default
 * Tomcat connector (blocking servlet I/O, not webflux/Netty).
 */
@SpringBootApplication
@RestController
public class TomcatHttpsApp {

    @GetMapping("/phase5c2-tomcat")
    public String hello() {
        return "hello-from-tomcat phase=5c2\n";
    }

    public static void main(String[] args) {
        SpringApplication.run(TomcatHttpsApp.class, args);
    }
}
