# Inferno CRD client suite fixtures

Used by `InfernoCrdClientSuiteTest` (see [docs/inferno.md](../../../../../docs/inferno.md)).

- `complete-prefetch-requests.json` and `subset-prefetch-requests.json` are
  the CRD 2.2.1 hook request bodies that the Inferno CRD **server** suite
  sends to the Inferno CRD **client** suite's two simulated services. They
  are the `*_request_bodies` inputs of
  `config/presets/server_v221_against_inferno_crd_client_suite.json.erb` and
  `config/presets/server_v221_against_inferno_crd_client_suite_prefetch_subset.json.erb`
  in [inferno-framework/davinci-crd-test-kit](https://github.com/inferno-framework/davinci-crd-test-kit)
  v0.14.2 (commit `35dd6ff5cde916e2b1c72f4ce5ac377e1e4fb491`), keyed by hook
  name. The ERB expression `<%= Inferno::Application['base_url'] %>` is
  replaced by `{{inferno}}`, which the test fills in with the Inferno base URL.
  Copyright The MITRE Corporation, Apache License 2.0.
- `expected-results.json` records the outcome this library gets for each
  Inferno test, with the reason for every result that is not a pass. The
  test fails when a run differs from it.
