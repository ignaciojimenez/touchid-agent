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
