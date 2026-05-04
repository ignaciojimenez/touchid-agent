# Post-create hooks

Run an executable after key creation with `-post-hook PATH`. The value
must be a path to an executable file, not a shell expression. The
executable receives key details via environment variables:

| Variable | Description |
|----------|-------------|
| `TOUCHID_AGENT_LABEL` | Key label (e.g., `ssh`, `git`) |
| `TOUCHID_AGENT_PUBKEY` | Full SSH public key string |
| `TOUCHID_AGENT_PUBKEY_FILE` | Path to the `.pub` file |
| `TOUCHID_AGENT_TOUCH_REQUIRED` | `true` or `false` |

The hook is executed directly (not through a shell), so inline shell
syntax like `echo $VAR` or pipes will not work. If you need shell
features, write a script file and pass its path.

## Examples

Upload to GitHub on creation:

```bash
touchid-agent -create ssh -post-hook contrib/hooks/github-upload.sh
```

Configure git signing and upload the signing key:

```bash
touchid-agent -create git -no-touch -post-hook contrib/hooks/github-signing.sh
```

Write your own hook for any provisioning system -- LDAP, Vault, SCIM, or a
corporate API. See `contrib/hooks/` for examples.
