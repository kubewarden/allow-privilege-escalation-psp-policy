
 Continuous integration | License
 -----------------------|--------
![Continuous integration](https://github.com/chimera-kube/psp-allow-privilege-escalation/workflows/Continuous%20integration/badge.svg) | [![License: Apache 2.0](https://img.shields.io/badge/License-Apache2.0-brightgreen.svg)](https://opensource.org/licenses/Apache-2.0)

This Chimera Policy is a replacement for the Kubernetes Pod Security Policy
that limits the usage of the [`allowPrivilegeEscalation`](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

# How the policy works

This policy rejects all the Pods that have the `allowPrivilegeEscalation`
security context enabled.

The policy inspects also `initContainers`.

# Examples

The following Pod will be rejected because the nginx container has `allowPrivilegeEscalation`
enabled:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      allowPrivilegeEscalation: true
  - name: sidecar
    image: sidecar
```

The following Pod would be blocked because the `allowPrivilegeEscalation` is
enabled at the Pod level:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  securityContext:
    allowPrivilegeEscalation: true
  containers:
  - name: nginx
    image: nginx
  - name: sidecar
    image: sidecar
```

The following Pod would be blocked because one of the init containers has
`allowPrivilegeEscalation` enabled:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  securityContext:
    allowPrivilegeEscalation: true
  containers:
  - name: nginx
    image: nginx
  - name: sidecar
    image: sidecar
  initContainers:
  - name: init-myservice
    image: init-myservice
    securityContext:
      allowPrivilegeEscalation: true
```
# Obtain policy

The policy is automatically published as an OCI artifact inside of
[this](https://github.com/orgs/chimera-kube/packages/container/package/policies%2Fpsp-allow-privilege-escalation)
container registry.

# Using the policy

The easiest way to use this policy is through the [chimera-controller](https://github.com/chimera-kube/chimera-controller).
