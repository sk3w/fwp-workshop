# Fun With Protocols Workshop

This repository contains the code and supporting materials for the 2024 Hack Red Con workshop "Fun With Protocols: Write a MITM Proxy with Rust" on October 26.

## Instructions

You will need to install the following prerequisites on your local machine:

- Install rust and cargo via https://rustup.rs (version 1.82.0 at the time of this writing)
- Install [VS Code](https://code.visualstudio.com) (or your preferred editor)
- Install the [`rust-analyzer`](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer) and [`Even Better TOML`](https://marketplace.visualstudio.com/items?itemName=tamasfe.even-better-toml) extensions
- Install [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
- Install [Wireshark](https://www.wireshark.org/download.html)

Then, checkout this repository on your local machine (`git clone https://github.com/sk3w/fwp-workshop.git`).
During the workshop, participants are invited to follow along and interactively write code as we go.
You can also use the following git branches to skip to different points in the overall development process:

- "1-datatypes"
- "2-parser"
- "3-codec"
- "4-client"
- "5-server"
- "6-proxy"
- "7-complete"

For example, if you want to move past creating the initial data types and start working on the parser (step 2), first make sure you have the branches fetched locally:

`git fetch --all`

and then checkout the branch corresponding to the "parser" step:

`git checkout origin/2-parser`
