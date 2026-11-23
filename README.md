# SecureBB

A security layer for [bb](https://github.com/get-bb/bb), an open-source IDE where coding agents run in threads and write plugins for the IDE itself. SecureBB is a bb plugin plus a small guard daemon. Its goal: agents keep working on their own, but a person decides which code gets loaded into the IDE.

bb is gaining users quickly, and its trust model was designed for one developer on one laptop. This project is an attempt to make it safe for a stricter case, and a record of how far a plugin can take that.

**Status:** working, on hold. The remaining gaps can only be closed in bb's core (see [Where a plugin stops](#where-a-plugin-stops)). The interface and the detailed reference ([docs/REFERENCE.ru.md](docs/REFERENCE.ru.md)) are in Russian.

## The problem

In bb, an agent can write a plugin, and an installed plugin runs with full trust inside the server. bb's local HTTP API has no authentication; its security policy says so directly: "unauthenticated by design". That is a reasonable choice for one developer on one laptop, where the agent is treated as the user.

SecureBB targets a different case: agents that run for hours unattended, read the web and other people's repositories, and so may end up acting on someone else's instructions. Here the agent is untrusted, and it must not be able to decide on its own which code gets loaded into the IDE.

## What it does

- **Gate on plugin code.** A plugin version loads only if a person approved its content hash, or it arrives inside a trust window opened by a person for one plugin and one thread. Unknown versions are held in a review queue.
- **Checks before approval.** Static checks of the plugin source (AST, file set, data flow from secrets to the network, which SDK rights the code uses) and of dependencies (lookalike names, registry state, versions). They produce a short list of rights the plugin asks for: "runs programs", "goes to the network", "reads secrets".
- **Trust windows.** A window slides while the agent works and has a cap. It closes by itself when the thread reads untrusted input (a web page, a foreign repository, an MCP server), because from that moment the agent may be acting on someone else's instructions.
- **Second factor on decisions.** TOTP or a passkey, because without API authentication an agent can call the same endpoint the "Approve" button calls.
- **Guard daemon.** Approvals, windows, the second-factor secret and a hash-chained journal live in a separate process under a separate OS user, so an agent that takes over the server's user still cannot forge an approval.
- **Config and skills watcher.** Detects and can roll back changes to bb settings, agent instructions, skills and providers made outside an approved window.
- **Optional AI review** of plugin code, and an optional AI observer of agent actions (observation only).
- **Honest status page.** It shows which protection level the install is really at and what is not protected.

The strongest mode needs three OS users (server, agents, guard) and a small patch to bb's core that asks the guard before loading plugin code. The patch and the installer are not in this repository. On stock bb the plugin works in a weaker "after the fact" mode: it disables an unapproved plugin after it has already started.

## Design decisions

Most of the design follows from one fact: **the bb server cannot tell an agent from a person.** Any local process can call the endpoint behind the "Approve" button. Each mechanism answers a specific consequence of that:

| Mechanism | What it answers | Still needed once bb has scoped agent credentials |
|---|---|---|
| Separate OS users | Agents must not reach the owner's home directory, SSH keys and Keychain | Yes |
| Checks and a rights report at install time | A person should see what a plugin can do before it runs with full trust | Yes, in a simpler form |
| Second factor on approvals | An agent can call the approval endpoint itself | No |
| Guard daemon under its own user | An agent could edit the plugin's own database | No |
| Config watcher, trust windows | An agent can change settings and install plugins | No |
| "Guard is not answering" alarms | An agent could stop the guard | No |

Built with agents inside bb from a written specification and threat model, stage by stage, each stage reviewed by a model from a different family. About 38,000 lines of TypeScript with tests, around 1,980 tests, no runtime dependencies beyond Node and the bb SDK.

## Where a plugin stops

Two limits cannot be removed from outside bb's core:

- **Identity.** Without authentication in the API, every protection has to assume the agent can imitate the person. That is why approvals need a second factor, and why the daily interface carries codes, windows and alarms. This level of friction is acceptable for a security engineer and too much for most users.
- **Plugin rights.** The checks report what a plugin can do, but nothing enforces it once the plugin runs.

What closes them, in the core:

1. each thread gets its own scoped credential;
2. approvals, plugin installs and settings need an operator credential;
3. plugin rights are enforced at run time, not only reported.

bb's maintainers track local API authentication in [get-bb/bb#3708](https://github.com/get-bb/bb/issues/3708), including the requirement that agents must not receive the unrestricted install secret. Two concrete findings from this project are posted there ([comment](https://github.com/get-bb/bb/issues/3708#issuecomment-7095775704)): the routes an agent can use to approve its own request, and an enrollment route open to any local process.

When scoped agent credentials land, SecureBB can be rewritten as a much smaller plugin: checks and a rights report at install time, on top of OS user separation. The second factor, the guard daemon, the watcher, the windows and the alarms become unnecessary, and the protection stops being visible in everyday work.

## Repository map

| Path | What |
|---|---|
| `server.ts`, `src/` | Plugin server side: gate, queue, windows, journal, CLI commands |
| `guard/` | The guard daemon, no dependencies, runs from source ([guard/README.md](guard/README.md)) |
| `guard/src/checks/`, `guard/src/deps/` | Static and dependency checks |
| `app.tsx`, `app/`, `components/` | The SecureBB page inside bb |
| `skills/` | The skill that tells agents how to propose a plugin |
| `test/` | Tests |
| `docs/REFERENCE.ru.md` | Full reference, stage by stage (Russian) |

Tests run with `npm test` and need bb's plugin SDK available locally.

## License

MIT.
