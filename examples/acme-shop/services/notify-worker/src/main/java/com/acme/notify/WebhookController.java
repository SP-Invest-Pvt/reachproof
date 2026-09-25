package com.acme.notify;

import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WebhookController {
    private static final Logger log = LogManager.getLogger(WebhookController.class);
    private final DeliveryQueue queue;

    public WebhookController(DeliveryQueue queue) {
        this.queue = queue;
    }

    @PostMapping("/webhooks/carrier")
    public ResponseEntity<String> carrierEvent(@RequestHeader("User-Agent") String agent,
                                               @RequestBody CarrierEvent event) {
        ThreadContext.put("requestId", UUID.randomUUID().toString());
        String caller = agent.trim();
        log.info("Carrier webhook received from {}", caller);
        queue.enqueue(event);
        return ResponseEntity.accepted().body("queued");
    }
}
