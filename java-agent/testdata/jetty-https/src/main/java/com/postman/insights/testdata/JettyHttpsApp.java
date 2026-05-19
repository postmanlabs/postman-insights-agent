// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.testdata;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Phase 5c.2 Jetty HTTPS workload — Spring Boot using Jetty instead of Tomcat. */
@SpringBootApplication
@RestController
public class JettyHttpsApp {

    @GetMapping("/phase5c2-jetty")
    public String hello() {
        return "hello-from-jetty phase=5c2\n";
    }

    public static void main(String[] args) {
        SpringApplication.run(JettyHttpsApp.class, args);
    }
}
