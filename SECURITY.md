# Security policy

## Scope

This repository is a **demonstration** with a simulated executor and synthetic data. It is not deployed anywhere and holds no real credentials. Even so, a flaw in its controls (for example, a way to bypass the approval gate, forge or replay an approval, escape the allowlist, tamper with the audit log undetected, or make the agent report success falsely) is exactly the kind of issue worth reporting, because people may copy the design.

## How to report

* **Preferred:** use GitHub's private vulnerability reporting. On the repository page choose **Security**, then **Report a vulnerability**, and include the steps to reproduce.
* If that option is not available, open a GitHub issue titled "Security contact request" **without** exploit details, and the maintainer will arrange a private channel.

Please include: the affected file or control, what you expected versus what happened, minimal reproduction steps (a ticket, approval, or log file is ideal), and the commit you tested.

## What to expect

This is a personal project maintained on a best-effort basis. I aim to acknowledge reports within about a week and to fix or document confirmed issues, crediting reporters who want credit. There is no bug bounty and no service-level agreement.

## Out of scope

* Weaknesses already listed under "Known limitations" in the README and in `THREAT_MODEL.md` (for example, shared-secret approval signatures and the need for external log anchoring in a real deployment).
* Results that depend on a live large language model, which this repository does not ship or test.
* Anything involving real systems or real personal data. Please do not test against systems you do not own.

Never post real secrets, tokens, or personal data in an issue or report.
