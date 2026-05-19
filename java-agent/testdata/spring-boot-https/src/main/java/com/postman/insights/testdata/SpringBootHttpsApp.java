// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.testdata;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

/**
 * Phase 5c.1 — Spring Boot 3.2 webflux HTTPS workload.
 *
 * <p>Launches an embedded Netty server on {@code https://127.0.0.1:8443}
 * with a single endpoint {@code GET /phase5c1} returning a fixed body.
 * Used to test whether our 5b.2 {@code SSLEngineInst} already captures
 * Spring Boot traffic, or whether we need a dedicated
 * {@code NettySSLHandlerInst}.</p>
 *
 * <p>SSL config lives in {@code application.yml} alongside this class.
 * The keystore at {@code /tmp/spring-boot-https-keystore.p12} is
 * auto-generated on first run by {@code launcher.sh}.</p>
 */
@SpringBootApplication
@RestController
@RequestMapping("/")
public class SpringBootHttpsApp {

    @GetMapping("/phase5c1")
    public Mono<String> phase5c1() {
        return Mono.just("hello-from-spring-boot phase=5c1\n");
    }

    public static void main(String[] args) {
        SpringApplication.run(SpringBootHttpsApp.class, args);
    }
}
