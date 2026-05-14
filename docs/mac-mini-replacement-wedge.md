# Mac Mini Replacement Wedge

Agentbox is for users who would otherwise run autonomous agents on a separate
machine because they do not trust those agents with their real workstation.

The wedge is not "a cheaper Mac mini" in a literal hardware sense. The wedge is
a local software boundary for the same underlying need:

```text
I want the agent to work locally,
but I do not want it to inherit my real machine by default.
```

## Why Separate Machines Happen

A dedicated machine gives users a simple mental model:

- separate filesystem
- separate credentials
- separate browser profile
- separate shell history and services
- lower blast radius if the agent goes wrong

That model is expensive and awkward, but it is understandable. Agentbox should
respect why people choose it instead of dismissing the behavior.

## What Agentbox Replaces

Agentbox should replace the need for a separate machine for common agent tasks
by providing a governed local minipod:

- a narrow workspace instead of the whole home directory
- explicit credential grants instead of ambient credentials
- network policy and evidence instead of silent egress
- approval gates for dangerous host actions
- audit and session evidence after the run
- provider-specific boundaries that get stronger over time

This is enough for many coding, research, DevOps, and personal workflow tasks.

## What Agentbox Does Not Replace Yet

Agentbox should not claim to replace dedicated hardware for every threat model.

Dedicated hardware or VM-backed isolation is still the right answer when:

- the user expects a malicious agent
- kernel compromise is in scope
- the agent needs a real browser profile boundary today
- wallet/keychain isolation must be hard, not policy-mediated
- enterprise compliance requires a hardware or VM boundary
- native provider live tests have not proven the needed OS behavior

The honest claim is: Agentbox reduces the need for a separate machine for many
local agent workflows. It is not a bypass-proof hardware substitute today.

## Product Shape

The product should feel like a local agent workbench, not like a VM console:

```text
agent intent
  -> minipod manifest
  -> local AgentPod session
  -> governed host boundary
  -> approval / evidence
```

The user should not have to think about containers, VMs, cgroups, Endpoint
Security, or WFP during ordinary use. Those are provider internals.

## Wedge Demo

A credible 60-second demo:

1. Start a common local agent in an Agentbox minipod.
2. Let it edit and test code inside the workspace.
3. Show that sensitive host paths are not available by default.
4. Let it attempt `git push` or a deploy command.
5. Agentbox asks for approval.
6. The user approves or denies.
7. Export the evidence bundle showing the decision, transcript, and workspace
   diff reference.

This tells the truth: Agentbox helps the agent work while narrowing the host
blast radius.

## Messaging Rules

Say:

- local-first governed runtime for autonomous agents
- software boundary for users who would otherwise dedicate a machine to agents
- minipods for task-scoped local execution
- approval and evidence for host-impacting actions
- native providers are becoming the enforcement layer

Do not say:

- impossible to bypass
- replaces hardware isolation for all threat models
- full browser/keychain/wallet isolation before provider proof
- eBPF/WFP/Endpoint Security enforcement before live denial tests
- Podman is the final architecture

## Success Criteria

This wedge is working when a user can say:

1. I can run my agent locally without giving it my whole machine.
2. I can see what credentials, files, and network destinations it is allowed to
   use.
3. Dangerous actions ask me first or fail closed.
4. I can inspect what happened after the session.
5. I understand which boundaries are shipped and which are still planned.
