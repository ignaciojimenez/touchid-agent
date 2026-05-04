# Git commit signing

Create a key for signing (Touch ID not required for automated operations):

```bash
touchid-agent -create git -no-touch
```

Configure git to use it:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/touchid-agent-git.pub
git config --global commit.gpgsign true
```

## Verifying signatures locally

Git can verify SSH signatures with an `allowed_signers` file:

```bash
# Create the allowed_signers file with your email and public key
echo "$(git config user.email) $(cat ~/.ssh/touchid-agent-git.pub)" >> ~/.ssh/allowed_signers

# Tell git where to find it
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

Verify signatures on commits:

```bash
git log --show-signature
git verify-commit HEAD
```

Add additional trusted signers (teammates, CI) by appending lines to
`~/.ssh/allowed_signers` in the format `email key-type key-data`.
