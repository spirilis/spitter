# Prometheus Metrics for this application

Proposed metrics this application should collect:

* WebhookServer
  * spitter_webhook_routers - how many routers are we using
  * spitter_webhook_routers_rejected - how many routers were rejected during setup due to invalid config
  * spitter_webhook_requests - how many Alertmanager webhooks have we received
  * spitter_webhook_requests_attempted - how many Alertmanager webhooks have we processed & attempted to route
  * spitter_webhook_requests_successful - how many Alertmanager webhooks have we processed, attempted to route and were successful
  * spitter_webhook_connections - how many webhook server requests are in flight (connection count)
* AlertmanagerWebhookTemplateV4
  * get a map of labels that have been matched by existing routers and create a new instance of a prometheus counter with label="<thatlabel>", increment the counter every time we route one for it
  * total number of individual alerts received
  * total number of individual alerts routed
  * total number of Status=firing alerts routed
  * total number of Status=resolved alerts routed

