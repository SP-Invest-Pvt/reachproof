package com.acme.notify;

import java.util.concurrent.ConcurrentLinkedQueue;
import org.springframework.stereotype.Component;

@Component
public class DeliveryQueue {
    private final ConcurrentLinkedQueue<CarrierEvent> pending = new ConcurrentLinkedQueue<>();

    public void enqueue(CarrierEvent event) {
        pending.add(event);
    }
}
