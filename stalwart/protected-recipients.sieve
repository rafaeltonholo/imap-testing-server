require ["envelope", "reject"];

if envelope :is "to" "dashboard-management@local.test" {
    reject "550 5.7.1 Recipient is reserved for dashboard management.";
}

if envelope :matches "to" "dashboard-management+*@local.test" {
    reject "550 5.7.1 Recipient is reserved for dashboard management.";
}
