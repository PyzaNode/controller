# pyzanode/controller

Central API and WebSocket server for PyzaNode: node registry, server lifecycle, presets, log streaming to the dashboard. Serves the embedded dashboard at `/dashboard/` when built with the web UI.

## Build

From this directory:

```bash
go build -o pyzanode-controller .
```

Cross-compile (e.g. Linux from Windows): `GOOS=linux GOARCH=amd64 go build -o pyzanode-controller .`

To get the embedded dashboard, build the dashboard first (`cd dashboard && npm run build`), then build the controller. Or use the full build from the directory that contains `scripts/` and the component repos: `scripts/build-all.bat` / `scripts/build-all.sh` (see [scripts/README](https://github.com/PyzaNode/scripts/blob/main/README.md)).

## Run

```bash
./pyzanode-controller
```

Optional: `-web <dir>` to serve a dashboard from a directory instead of the embedded one (e.g. `dashboard/dist` if you built with `outDir: 'dist'`).

First run creates the data dir (default `~/.pyzanode`), generates a token, and prints the agent connect command. Listens on `http://0.0.0.0:9451`.

## Deps

`github.com/pyzanode/shared` for config and types.

## License

See the [project license](https://github.com/PyzaNode/.github/blob/main/profile/LICENSE).
