package com.acme.orders;

public record OrderView(String id, String sku, int quantity, String status) {}
