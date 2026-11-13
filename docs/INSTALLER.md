# Reviewed local setup

Source/data packages remain inert: they do not run this installer, initialize accounts, migrate data or start services. The KagNode CLI calls this project-owned entrypoint only after displaying a fresh plan for explicit local review:

```text
python3 scripts/kagnode-installer.py plan|apply|status|health|recover --request PRIVATE_REQUEST --output NEW_PRIVATE_OUTPUT
```

Requests and outputs use schema 1. The request is a private regular file owned by the invoking user, with a unique 32-character hexadecimal `operation_id`, the matching `project`, an absolute shared `root`, a supported `mode` and typed `configuration`. Never pass secret values in command arguments. Password fields reference private files; they are not inline passwords.

`plan` returns configuration fields even when required values are missing. Such a plan has `ready_for_apply:false` and cannot be applied. A complete plan includes the current platform, prerequisites, exact configuration, source inventory digest, managed paths, operations and health scope. `apply` recomputes the plan and requires its exact `review.plan_sha256`; drift requires a new review. Exit code zero alone is not a readiness result.

## Supported scope

Installed management processes and project state. Client connectivity and tunnel behavior remain separate verification.

This native adapter hands off to the existing project console in a real controlling terminal. The CLI leaves its raw TUI before handoff. Piped/noninteractive application is rejected; exit from the console is followed by independent health checks. The original native installer still owns its locks, prompts and configuration policy.

## Existing installations and recovery

`adopt` inspects existing known code/configuration/data locations without moving or replacing them. It records a binding only after independent health succeeds. Legacy native paths and service identities remain compatible; an incomplete installation is reported honestly and is not silently reinitialized. Standalone health/status does not require fresh setup passwords.

Each mutation has a private operation journal. Recovery requires the original operation ID and configuration, the same reviewed source, and a new plan with `intent:"recover"`. Completed steps are retained; differing configuration, unknown user data and mismatched source are not overwritten. An interrupted account/credential initialization may need local inspection before resuming; recovery never guesses a password reset or restores an old database over new data. Keep backups outside the code tree.

Cancellation terminates and reaps only the operation's owned child process group, then records incomplete recovery state. Interactive foreground ownership is restored. Native services already installed through systemd are retained for explicit recovery; SIGKILL/power failure cannot execute a cleanup handler. A pending journal is never proof of success.

## Verification limits

Tests use disposable directories and injected process/platform operations to check exact-plan review, source/configuration drift, existing-data refusal, private file rules, TTY requirements, cancellation and health-gated completion. They do not provision a native host, qualify a mail/network service, execute FFmpeg, build an HTTP Boot image or establish hardware support. Existing product-specific verification records remain authoritative.

## Runtime updates

Successful setup records the installed code, configuration, data and service paths, reviewed source version/hash, and the runtime version observed by health when available. Adoption leaves unknown provenance unset. This adapter has no runtime update operation: downloading source or moving a source `current` link does not update its separately installed runtime. The CLI must not report that as a running-service upgrade. Existing verified native update procedures remain separate.
