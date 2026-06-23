# sshenv

SSH key profile manager — switch between named SSH key pairs stored in `~/.ssh/archive/`.

## Install

```sh
brew install gndps/tap/sshenv
```

## Usage

```sh
sshenv init work        # archive current keys as "work" and activate
sshenv activate personal  # switch to "personal" profile
sshenv list             # list profiles (* = active)
sshenv switch           # cycle to next profile alphabetically
sshenv new              # generate a new SSH key pair interactively
sshenv copy             # copy active public key to clipboard
```

## Commands

| Command | Description |
|---------|-------------|
| `init <profile> [-f]` | Archive current `~/.ssh/id_*` keys as a profile |
| `activate <profile>` | Copy archived keys to `~/.ssh/` |
| `list` | List all profiles; active marked with `*` |
| `switch` | Cycle to next profile |
| `delete <profile> -f` | Delete a profile |
| `new` | Interactively generate a new key pair |
| `clear [-f]` | Remove current `~/.ssh/id_*` files |
| `locate` | Print path of the default SSH key |
| `copy [profile]` | Copy public key to clipboard |
| `inject --host <host> --profiles <p1> [p2...]` | rsync profiles to a remote host |
