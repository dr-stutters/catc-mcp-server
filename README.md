# catc-mcp-server

MCP server for Cisco Catalyst Center (formerly DNA Center), built on
[stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core).

> Status: in development (milestone 1: scaffold, login and status).

```bash
uv sync
cp .env.example .env   # set CATC_URL / CATC_USERNAME / CATC_PASSWORD
uv run catc-mcp-server check
```

Not affiliated with or endorsed by Cisco Systems, Inc.
