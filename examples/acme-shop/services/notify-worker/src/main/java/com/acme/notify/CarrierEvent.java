package com.acme.notify;

public record CarrierEvent(String trackingId, String status, long timestamp) {}
