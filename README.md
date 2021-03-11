
 Continuous integration | License
 -----------------------|--------
![Continuous integration](https://github.com/chimera-kube/psp-allow-privilege-escalation/workflows/Continuous%20integration/badge.svg) | [![License: Apache 2.0](https://img.shields.io/badge/License-Apache2.0-brightgreen.svg)](https://opensource.org/licenses/Apache-2.0)

This Chimera Policy is a replacement for the Kubernetes Pod Security Policy
that limits the usage of the [`allowPrivilegeEscalation`](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).

# How the policy works

This policy allows only a selected list of users and groups of users to 
schedule Pods that have `allowPrivilegeEscalation` enabled.

# Configuration

The policy can be configured with the following data structure:

```yml
allowed_groups: # list of groups
- administrators
- system:masters
allowed_users: # list of users
- alice
- joe
```

Let's go through each field:
  * `allowed_users`: list of users that are unaffected by this policy. Optional.
  * `allowed_groups`:  list of groups that are unaffected by this policy. Optional.

Leaving both fields unspecified will prohibit all users from creating Pods with
`allowPrivilegeEscalation` enabled.

# Obtain policy

The policy is automatically published as an OCI artifact inside of
[this](https://github.com/orgs/chimera-kube/packages/container/package/policies%2Fpsp-allow-privilege-escalation)
container registry:

# Using the policy

The easiest way to use this policy is through the [chimera-controller](https://github.com/chimera-kube/chimera-controller).
