# Evidence index

Create one directory per rung, for example:

```text
evidence/
  p0b_build_bank/
  p0c_capture_validation/
  p0d_endpoint_inventory/
  p0e_auth_map/
  p0f_transport/
  p0g_uds_audit/
```

Each directory should contain:

- `REPORT.md`
- `MANIFEST.json`
- sanitized extracts only
- hashes of local-only raw artifacts

Use `scripts/hash_tree.ps1` or `scripts/hash_tree.sh` to build a hash manifest without committing raw files.
