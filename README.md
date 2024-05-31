[![Kubewarden Policy Repository](https://github.com/kubewarden/community/blob/main/badges/kubewarden-policies.svg)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#policy-scope)
[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)

This policy rejects all the Pods that have at least one container or
init container with the `allowPrivilegeEscalation` security context
enabled.

The policy can also mutate Pods to ensure they have `allowPrivilegeEscalation`
set to `false` whenever the user is not explicit about that.
This is a replacement of the `DefaultAllowPrivilegeEscalation` configuration
option of the original Kubernetes PSP.

## Settings

The policy can be configured in this way:

```yaml
default_allow_privilege_escalation: false
```

Sets the default for the allowPrivilegeEscalation option. The default behavior without this is to allow privilege escalation so as to not break setuid binaries. If that behavior is not desired, this field can be used to default to disallow, while still permitting pods to request allowPrivilegeEscalation explicitly.

By default `default_allow_privilege_escalation` is set to `true`.

This policy can inspect Pod resources, but can also operate against "higher order"
Kuberenetes resource like Deployment, ReplicaSet, DaemonSet, ReplicationController,
Job and CronJob.

It's up to the operator to decide which kind of resources the policy is going to inspect.
That is done when declaring the policy.

There are pros and cons to both approaches:

- Have the policy inspect low level resources, like Pod. Different kind of Kubernetes
  resources (be them native or CRDs) can create Pods. By having the policy target Pod
  objects, there's the guarantee all the Pods are going to be compliant. However,
  this could lead to some confusion among end users of the cluster: their high level
  Kubernetes resources would be successfully created, but they would stay in a non
  reconciled state. For example, a Deployment creating a non-compliant Pod would be
  created, but it would never have all its replicas running. The end user would
  have to do some debugging to finally understand why this is happening.
- Have the policy inspect higher order resource (e.g. Deployment): the end users
  will get immediate feedback about the rejections. However, there's still the
  chance that some non compliant pods are created by another high level resource
  (be it native to Kubernetes, or a CRD).

## Examples

The following Pod will be rejected because the nginx container has
`allowPrivilegeEscalation` enabled:

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

The following Pod would be blocked because one of the init containers
has `allowPrivilegeEscalation` enabled:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
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
