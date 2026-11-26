# Lessons

- **Anything in a chart that can cut traffic is off by default.** I shipped the NetworkPolicy with `enabled: true`,
  reading "make sure the chart adds a NetworkPolicy" as default-on; the user corrected it on 2026-11-25:
  "The NetworkPolicy needs to be off by default." A policy whose selectors miss Alertmanager silently stops every
  alert on `helm upgrade`. Rule: every optional object, built-in kinds included, renders only when its `enabled: true`
  is set, the same as the optional CRD objects in the user's standard kit. "Add support for X" in a chart means an
  opt-in X.
