package com.acme.billing;

import java.time.LocalDate;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class InvoiceRun {
    private static final Logger LOG = LogManager.getLogger(InvoiceRun.class);

    public static void main(String[] args) {
        LocalDate period = LocalDate.now().withDayOfMonth(1).minusMonths(1);
        List<Invoice> invoices = new InvoiceRepository().openInvoicesFor(period);
        int issued = 0;
        for (Invoice invoice : invoices) {
            invoice.issue();
            issued++;
        }
        LOG.info("Invoice run for {} complete: {} issued", period, issued);
    }
}
