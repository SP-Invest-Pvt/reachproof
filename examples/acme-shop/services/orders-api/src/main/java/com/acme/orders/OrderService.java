package com.acme.orders;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;

@Service
public class OrderService {
    private final Map<String, OrderView> store = new ConcurrentHashMap<>();

    public OrderView place(NewOrder order) {
        OrderView view = new OrderView(UUID.randomUUID().toString(), order.sku(), order.quantity(), "PLACED");
        store.put(view.id(), view);
        return view;
    }

    public Optional<OrderView> find(String id) {
        return Optional.ofNullable(store.get(id));
    }
}
