# Historical RC.1 candidate qualification

RC.1 was never published. Current work qualifies stable 4.0.0 directly; follow
[stable testing](STABLE_TESTING.md). The instructions below retain the earlier RC process.

`4.0.0-rc.1` is not a published release. The published
evaluation release remains beta.2. Do not create its Git tag until all gates pass.

## Builder checks

Run the full suite and native export/kernel/systemd checks, package lifecycle and
beta.2 upgrade preservation, browser checks and a deployed legacy-reset rehearsal.
Keep test identities and raw evidence private. Record sanitized outcomes in
`qualification/4.0.0-rc.1.json` with the SHA-256 of the final generated installer.
An implementation change invalidates affected evidence and restarts observation.
The release workflow refuses RC/stable publication without matching evidence.

Use one VM at a time: 1024 MiB guest memory, 1536 MiB host process limit, and a
2 GiB MemAvailable stop guard. Browser tests run separately under a 512 MiB cap.
Do not stop other workspace jobs to make room. A simulated browser is not iPad evidence.

## Existing beta.2 server

1. Confirm `vpn --version`, console recovery access, free disk, memory and service
   health. Verify a root-only recovery backup including private state, configuration,
   native NSS trust, WireGuard and PPP files. Never send that backup or credentials
   through public delivery. Preserve Ubuntu networking and the SSH setup choice.
2. Transfer the signed candidate using the established private access method.
   Verify its manifest against the installed pinned key, then its asset checksums.
   Agree on the update window; run `sudo bash update.sh --prerelease` locally.
3. Verify the new version, automatic services, DNS, dashboard login/MFA, policies
   and profiles. Compare private identity hashes before/after. Repair existing
   clients rather than replacing credentials simply to make a test pass.
4. Run a system connection check under System and a device check from its Profiles
   page. Findings are snapshots; rerun after connecting. Support reports are
   Owner-only, redacted and contain no raw journal or client identifiers.

## Guided iPad and WAN checks

Use a dedicated test device identity with a separately communicated import password.
Publish a native Apple profile link, open it in Safari, allow the download, and
install through Settings → General → VPN & Device Management. Confirm one total
download, used-token rejection and revoke/reissue behavior. Do not include passwords
in QR codes, email drafts, screenshots or reports.

Connect IKEv2 on home Wi-Fi, then through a genuinely independent network such as
a phone hotspot using mobile data. Confirm the hotspot is not forwarding the home
Wi-Fi connection. Check DNS, internet access, allowed resources and denied traffic.
Exercise disconnect/reconnect and sleep/wake. Run device diagnostics while connected.
Also exercise WireGuard and L2TP with compatible clients, policy enforcement and
revocation. Server-side checks do not establish router forwarding or WAN reachability.

Record OS versions, candidate digest, UTC times and pass/fail outcomes privately;
publish only sanitized summaries. A failure must retain evidence and receive a fix
and regression test before the candidate is qualified.

## 24-hour observation and publication

After functional checks pass, observe the final candidate for 24 completed hours.
Transfer the maintained `tools/observe_rc.py` helper privately, then run it under
a dedicated transient systemd service (64 MiB memory cap) with `--hours 24 --output
/var/log/vpn/rc-observation.jsonl`. It reads fixed service properties and memory
once per minute, adds aggregate queue/watchdog counters, makes no repairs, and
refuses to overwrite earlier evidence. It never exports job forms/results or raw
journals. Review both counters and the private audit/journal history.
Record service failures, watchdog/reboot actions, queue failures, memory readings,
routine maintenance and reconnect outcomes. Review root-only journals locally.
No unexplained crashes, reboot loops or sustained memory growth may remain.
Security updates retain the configured manual-reboot policy.

Complete the UTC observation timestamps and evidence in the qualification record.
Run `python3 tools/qualify_release.py`; missing evidence must fail. Freeze the tested
commit, pass CI and publish `v4.0.0-rc.1` through the signed draft-download workflow.
Verify the published downloads independently. Stable promotion is a later decision.
