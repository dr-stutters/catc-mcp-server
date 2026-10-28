# catc_change_window

title: Run a Day-N template change window
arguments: {"params": "{\"loopback_id\": 77}", "rollback": "negation", "targets": "r1.mcp.lab, r2.mcp.lab", "template": "mcp-test-dayn/mcp-test-loopback", "window_end": "2099-01-01T23:00+11:00"}

Run a safe Day-N change with Catalyst Center: baseline (issues, compliance, config archive),
per-device preview, safety-rail checks (device limit, window end), deploy, deployment status,
CLI verification, a compliance run, the config diff, a post-change issue diff, and a written
rollback plan. Offers a maintenance window so the change doesn't page anyone, and ends it after.
Deploying is dangerous-tier; without it the prompt stops at a reviewed plan.

## user

Change window: deploy template "mcp-test-dayn/mcp-test-loopback" to ["r1.mcp.lab", "r2.mcp.lab"] with params {"loopback_id": 77}.
The window closes at 2099-01-01T23:00+11:00. Work through the steps in order and stop on any failure.
Every write is preview-first: show the preview, wait for the user's approval, then repeat the call
with the confirm token. Keep a short log of each step's result for the summary.

1. Baseline, before touching anything (save the results; steps 8-9 compare against them):
   - `catc_get_device` for each device: it must be Reachable and Managed;
   - `catc_list_issues` with device=<each device>: the open issues now;
   - `catc_get_compliance_detail` for each device: per-category status now;
   - `catc_list_config_archive` for each device: the newest RUNNINGCONFIG file id and
     time (the pre-change version). If it is older than the device's last change, run
     `catc_resync_devices` first so the archive is current.
2. Template: `catc_get_template` for "mcp-test-dayn/mcp-test-loopback". It must be committed (a
   draft can't be deployed; offer `catc_commit_template`), and its device types must
   match the targets. List its variables and check {"loopback_id": 77} supplies the required ones.
3. Preview per device: `catc_preview_template` with params {"loopback_id": 77} and device=<each
   device>. Show the rendered CLI for each device and point out anything risky (interfaces shut,
   routing, AAA, ACLs on the management path).
4. Safety rails, all must pass before deploying:
   - at most 10 devices in one change (this one: 2);
   - the current time is before 2099-01-01T23:00+11:00, with enough time left for deploy + verification +
     a rollback (allow 15 minutes); otherwise stop and say the window is too short;
   - no P1/P2 issue open on a target in step 1 (or the user accepts it explicitly);
   - the user has approved the rendered CLI from step 3.
   - Maintenance window: `catc_list_maintenance_windows` for each device. If none covers
     now until 2099-01-01T23:00+11:00, offer `catc_schedule_maintenance` with devices=["r1.mcp.lab", "r2.mcp.lab"], start a
     few minutes from now, end 2099-01-01T23:00+11:00 and the change as description (show the preview: health and
     issues go dark for those devices, and the window runs to its end time: once started it can't be
     cancelled or moved, only ended now, so pick an end that covers deploy + verification). Wait until it is
     IN_PROGRESS before deploying. Without one, expect the change's own issues in step 9.
5. Deploy: `catc_deploy_template` with template "mcp-test-dayn/mcp-test-loopback", devices=["r1.mcp.lab", "r2.mcp.lab"],
   params {"loopback_id": 77}. Show the preview and wait for approval. If the tool isn't available (the
   dangerous tier is off on this server), stop here: hand the user steps 1-4 and the rollback
   plan (step 10) as the reviewed change plan.
6. Deployment status: `catc_get_template_deployment` with the deployment id until
   every device is SUCCESS (or one fails: then go to step 10 for that device).
   Verify on the devices: `catc_run_show_commands` with the show commands that prove
   the change (e.g. "show running-config | section <what the template touches>").
7. Config diff: `catc_resync_devices`, wait ~2 minutes, then
   `catc_compare_device_configs` with compare="previous" for each device. The '+'
   lines must be what the template rendered in step 3 and nothing else. If the result is
   identical or misses the change (the archive got no new version, or more than one), compare
   with compare="files", from_file=<step 1's file id> and to_file=<the newest RUNNINGCONFIG>.
8. Compliance: `catc_run_compliance` for ["r1.mcp.lab", "r2.mcp.lab"], then
   `catc_get_compliance_detail` again. Compare with the baseline: RUNNING_CONFIG
   (startup vs running) usually turns NON_COMPLIANT because Catalyst Center doesn't save the
   config; anything else that changed is a finding.
9. Issue diff: `catc_list_issues` per device again (and
   `catc_recent_activity` for the window) and report new issues since step 1. Inside a
   maintenance window the devices raise no issues: a quiet list proves nothing, so rely on steps 6-8.
   Once verified, end the silence: a started window can't be cancelled or given a new end time, so
   `catc_update_maintenance_window` with end_now=true (or `catc_cancel_maintenance`
   if it never started); if Catalyst Center refuses, it ends on its own at its end time. Then
   `catc_list_maintenance_windows` to see it COMPLETED, and `catc_list_issues`
   per device once more.
10. Rollback plan (always write it, even when everything passed):
   - Write the negation: for every line the template added (step 7's diff, '+'
     lines; if the deploy failed before step 7, use the rendered CLI from step 3), the
     'no ...' form, in dependency order (children before parents, e.g. 'no interface Loopback77'
     removes its sub-commands too). Offer to create it as "<template>-rollback" in the same project
     with `catc_create_template` + `catc_commit_template`, preview it with
     `catc_preview_template`, and (only if the user asks to roll back now)
     deploy it with `catc_deploy_template`.
   - Say when it must be started to finish before 2099-01-01T23:00+11:00.
11. Summary: what was deployed where, deployment result, verification output, config diff,
    compliance before/after, new issues, and the rollback plan. Suggest "write memory" (or a
    template) if the change should survive a reload.
