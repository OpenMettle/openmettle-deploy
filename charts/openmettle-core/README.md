# Core chart scaffold

This directory reserves the chart boundary. It currently contains metadata and an empty values object, with no Kubernetes resources. Do not treat a successful empty render or Helm install as application acceptance.

V1-32 adds API/worker Deployments, Services, configured database and artifact storage, restricted identities, probes, explicit images, values schema and tests. Core rendering must not require DRA CRDs or install any GPU resources. Optional managed-inference/accelerated-tool packages are separate.
