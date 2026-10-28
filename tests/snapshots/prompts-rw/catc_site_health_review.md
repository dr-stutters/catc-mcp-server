# catc_site_health_review

title: Weekly site health review
arguments: {"hours": "168", "site": "Global/mcp-test-lab/mcp-test-bldg"}

A weekly review of one site as a single ranked report: network, device and client health with
their trends and dips, open issues and the ones that keep coming back, compliance, software image
currency against the golden image, and template drift, with devices under a maintenance window
kept out of the findings, ending with next steps. Read tier: nothing changes; the next steps only
name the tools (writes among them are previewed when the user runs them).

## user

Review site Global/mcp-test-lab/mcp-test-bldg over the last 168 h and write one ranked report with next steps.
Read only: no tool below changes anything. Where a step's tool fails or Catalyst Center has no data for it,
say so in that section of the report ("not available: <reason>") and carry on; a missing section is not a
healthy one.

1. Scope. `catc_get_site` for "Global/mcp-test-lab/mcp-test-bldg" (it must exist; stop and say so if it doesn't), then
   `catc_list_devices` with site "Global/mcp-test-lab/mcp-test-bldg" (all pages; it includes the devices on every site below
   "Global/mcp-test-lab/mcp-test-bldg", such as a building's floors, and names each device's assigned site): hostname, IP, role,
   platform, software version, reachability, site. This device list is the scope of every later step; if
   it is empty while the site has child sites, say so instead of reporting an empty site as healthy.
2. Maintenance first. `catc_list_maintenance_windows` with site "Global/mcp-test-lab/mcp-test-bldg": note each window that is
   IN_PROGRESS now or overlapped the last 168 h (start, end, devices). Devices in maintenance mode raise no
   issues and get no health, and a change inside a window is expected: a device's health dip, issue or
   unreachability that falls inside its window is NOT a finding. List those devices in the report under
   "Under maintenance" with the window, and keep them out of the ranking. A device still unreachable or
   unhealthy after its window ended is a finding again.
3. Health now and over time. `catc_site_health_report` with site "Global/mcp-test-lab/mcp-test-bldg" and hours 168 (health
   now, device and client trends with dips and direction, worst devices and clients with the issue behind
   each, recurring issues, AI insights, verdict). Then `catc_health_trend` with scope "site",
   target "Global/mcp-test-lab/mcp-test-bldg" and hours 168 for the dips (when, how long, how low) and whether it is getting worse; for
   the network context `catc_get_network_health` (this site's row against the rest) and
   `catc_get_client_health`. Per device: `catc_list_device_health` with site "Global/mcp-test-lab/mcp-test-bldg"
   (POOR and FAIR devices, CPU/memory, link errors, reachability); trend a POOR device with
   `catc_health_trend` scope "device" to see whether it is new or chronic.
4. Issues. `catc_list_issues` with site "Global/mcp-test-lab/mcp-test-bldg", status "active" and hours 168 (the issues of
   "Global/mcp-test-lab/mcp-test-bldg" and its child sites, floors included); for each P1/P2
   `catc_get_issue` (root cause, suggested actions). Issues stay active for hours after they
   clear: compare last_seen with now and with the device's live reachability before calling one current.
   What keeps coming back: `catc_issue_recurrence` with site "Global/mcp-test-lab/mcp-test-bldg" and hours 168.
5. Compliance. `catc_compliance_report` with site "Global/mcp-test-lab/mcp-test-bldg" (non-compliant devices, failing
   categories and severity, policy rule violations; trend.since_previous_report says what is new and what was
   fixed); for the rule detail `catc_list_compliance_violations` with device set to each
   non-compliant device from that report (the tool needs a device, or a policy and a site). Note
   when the last compliance run is older than the window: the result is stale, and the next steps recommend
   `catc_run_compliance` for the site's devices.
6. Image currency. `catc_list_device_images` with site "Global/mcp-test-lab/mcp-test-bldg": NON_COMPLIANT devices do not run
   the golden image for their site and role (name the version they run); UNKNOWN means no golden image is
   tagged for that platform, which is itself a finding (low). `catc_list_images` with golden true
   and site "Global/mcp-test-lab/mcp-test-bldg" shows which golden images apply.
7. Template drift. `catc_template_drift` with drifted_only true (deployments of the last 30
   days): keep only the rows whose device is in the step 1 list. state behind = an older template version
   is deployed; failed = the last deployment never succeeded.
8. Rank the findings, most severe first, one line each: the device (or the site), what is wrong, the
   evidence (value and time), and the step that found it. Order:
   1. unreachable devices and P1 issues that are still current;
   2. POOR health (device or site) and P2 issues; a site or device trend that is still getting worse.
      direction "worse" compares the first and second half of the window, so a dip that has ended reads
      as worse too: before ranking it here, check the trend's latest value and its dips (a dip with an
      end and latest back above the dip threshold is recovered: rank it 6 as a past dip, with its
      start, end and lowest value; an ongoing dip or a latest still low stays here);
   3. compliance failures (security advisories and your compliance policies before startup vs running);
   4. devices not on the golden image;
   5. template drift (failed before behind);
   6. FAIR health, P3/P4 issues, recurring issues that are cleared now, recovered dips, no golden image
      tagged.
   Merge duplicates (a down link raising an issue and a POOR score is one finding). Devices under
   maintenance (step 2) never appear in the ranking.
9. Report: a one-line verdict for Global/mcp-test-lab/mcp-test-bldg (healthy, watch, or act now) with the counts per rank; the ranked
   findings; "Under maintenance"; "Not available" (sections Catalyst Center could not answer); and next steps,
   each naming the tool: `catc_get_issue` suggested commands with
   `catc_run_show_commands` for a current issue; `catc_run_compliance` for stale
   compliance (write tier, previewed); `catc_tag_golden_image` where no golden image is tagged and
   `catc_distribute_image` / `catc_activate_image` for devices off the golden
   image, inside a change window (prompt catc_change_window); `catc_preview_template` then
   `catc_deploy_template` to bring a drifted device to the latest committed version;
   `catc_device_360` for a POOR device.
   Run nothing from the next steps here: the user picks them.
