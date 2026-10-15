# catc_decommission_device

title: Decommission a device
arguments: {"clean_config": "false", "device": "r2.mcp.lab", "remove_ise_nad": "true"}

Take a device out of Catalyst Center cleanly: keep a copy of its configuration, show what
un-provisioning loses (it DELETES the device: unmanaged, assurance history and config archive
gone), untag it, delete it with an explicit clean_config, then remove the network device
Catalyst Center leaves behind in ISE. Every write is preview-first; needs the ise server for
the last step.

## user

Decommission "r2.mcp.lab" from Catalyst Center (clean_config=false). Show every
preview to the user and confirm only after they approve. Stop if a step fails and report what was done.

1. Identify: call `catc_device_360` for "r2.mcp.lab" and note hostname, management IP,
   serial, site, provisioning state and health. If it isn't found, stop: nothing to decommission.
2. Keep a copy: call `catc_get_device_config` for "r2.mcp.lab" (running config, secrets
   masked) and `catc_list_config_archive`; give the user the configuration or tell them
   where the archive versions are, because deleting the device deletes its archive in Catalyst
   Center.
3. Impact: call `catc_delete_device` with device "r2.mcp.lab" and clean_config=false
   WITHOUT confirm. Show the preview's side effects verbatim: un-provisioning in Catalyst Center 3.x
   deletes the device (no longer managed: no assurance, compliance, templates or provisioning until
   it is rediscovered), its archived configuration versions go, and with clean_config=true the
   AAA/syslog/SNMP/telemetry/banner configuration Catalyst Center pushed is removed from the device
   (it may lose RADIUS/TACACS+ logins that relied on it). If the user only wanted to stop managing
   some settings, suggest re-provisioning instead and stop here.
4. Tags: call `catc_list_tags`; for any static tag that has the device
   (`catc_list_tag_members`), remove it with `catc_update_tag_members`
   (remove=["r2.mcp.lab"]), so automation keyed on the tag doesn't target a ghost.
5. Delete: repeat `catc_delete_device` with the same arguments and the confirm token
   from step 3 (after the user approved it). Then `catc_get_device` for "r2.mcp.lab" must say
   no such device; `catc_get_task` if it is still running.
6. ISE: Catalyst Center does not delete the network device it created in ISE when it
   provisioned this device (with AAA = ISE). Call `ise_get_nad` with the device's
   management IP (from step 1); if one exists and its name is the device's hostname (CatC names it
   so, group DNAC#DNAC Devices), preview `ise_delete_nad` for it, show the preview and
   delete it once the user approves. If the NAD has another name or other IPs, show it and ask
   first: it may be shared or hand-made. Afterwards `ise_list_nads` filtered by the
   name confirms it is gone.
7. Summary: what was saved (config), what was removed (inventory entry, tags, ISE NAD), whether the
   device's configuration was cleaned, and how to bring it back: the `catc_onboard_device`
   prompt (discovery, site, provisioning).
