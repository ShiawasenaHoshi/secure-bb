# SecureBB

An experiment in protecting a coding-agent workspace from its own agents. It is a plugin for [bb](https://github.com/get-bb/bb) (an open-source IDE where agents run in threads and write plugins for the IDE itself) plus a small guard daemon.

**Status: frozen experiment, not a product.** It works on my machine, I ran it for a few days, and I concluded that most of it should not exist. This README says what it does, why it is built this way, and what I would keep. The interface and the detailed reference ([docs/REFERENCE.ru.md](docs/REFERENCE.ru.md)) are in Russian.

## The problem

In bb, an agent can write a plugin, and an installed plugin runs with full trust inside the server. bb's local HTTP API has no authentication; its security policy says so directly: "unauthenticated by design". That is a reasonable choice for one developer on one laptop, where the agent is treated as the user.

I wanted something else: agents that run for hours without me, read the web and other people's repositories, and still cannot decide on their own which code gets loaded into the IDE. So my threat model treats the agent as untrusted, and bb's does not. SecureBB is what you get when you try to build the first model on top of a product designed for the second.

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

## How it was built

Agents inside bb wrote most of the code. I wrote the specification and the threat model, split the work into stages, reviewed and merged every change, and ran each stage through a review by a model from a different family. About 38,000 lines of TypeScript with tests, around 1,980 tests, no runtime dependencies beyond Node and the bb SDK.

## What I learned

Almost every mechanism here compensates for one missing thing: **the server cannot tell an agent from a person.** Because of that:

| Mechanism | Why it exists | Verdict |
|---|---|---|
| Separate OS users | Keeps agents out of my home directory, SSH keys and Keychain | Keep |
| Checks and a rights report at install time | A person should see what a plugin can do before it runs with full trust | Keep, simplify |
| Second factor on approvals | An agent can call the approval endpoint itself | Needed only because the API has no auth |
| Guard daemon under its own user | An agent could edit the plugin's own database | Same |
| Config watcher, trust windows | An agent can change settings and install plugins | Same |
| "Guard is not answering" alarms | An agent could stop the guard | Same |
| AI observer of agent actions | Catch what the rules miss | Drop: it could not act, only report |

The second lesson is about people. I put security into the everyday interface: codes, windows, alarms, cards. After a few days I, the author, had to ask what all of it was for. Protection that needs a security engineer every day is not protection for ordinary users. It belongs in the installer and in the server's defaults, and should surface only when a person installs a plugin or issues a token.

## What should replace it

The right fix is in bb's core, not in a plugin:

1. each thread gets its own scoped credential;
2. approvals, plugin installs and settings need an operator credential;
3. plugin rights are enforced at run time, not only scanned.

bb's maintainers already track local API authentication in [get-bb/bb#3708](https://github.com/get-bb/bb/issues/3708), including the point that agents must not get the unrestricted install secret. I added two concrete findings there ([comment](https://github.com/get-bb/bb/issues/3708#issuecomment-7095775704)): the routes an agent can use to approve its own request, and an enrollment route open to any local process.

If scoped agent credentials land, I plan to rewrite this plugin as a small one: checks and a rights report at install time, on top of OS user separation. The second factor, the guard daemon, the watcher, the windows and the alarms go away.

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
