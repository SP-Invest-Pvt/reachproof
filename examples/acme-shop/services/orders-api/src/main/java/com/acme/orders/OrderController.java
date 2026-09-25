package com.acme.orders;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    private final OrderService orders;

    public OrderController(OrderService orders) {
        this.orders = orders;
    }

    @PostMapping("/orders")
    public ResponseEntity<OrderView> create(@RequestBody NewOrder request) {
        return ResponseEntity.ok(orders.place(request));
    }

    @GetMapping("/orders/{id}")
    public ResponseEntity<OrderView> get(@PathVariable String id) {
        return ResponseEntity.of(orders.find(id));
    }
}
