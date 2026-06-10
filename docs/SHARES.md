# External shares (NAS / NFS / SMB)

Any yard tool that writes log files can target a named **external share** in
addition to its local `/data` volume. Today that means **syslog-valve cache
nodes**; syslog-bucket retention exports will join later (PLAN, S5+).

The contract is deliberately small:

- **Mounting is the deployment's job, not the app's.** A share is anything
  mounted into the container at `/shares/<name>`.
- The tool's `YARD_SHARES` env lists which names to offer in the UI
  (`YARD_SHARES=archive,nas2` → `/shares/archive`, `/shares/nas2`).
  Names listed but not mounted are skipped with a warning at startup.
- Wherever the files land, the same retention applies: the valve compiles
  cache-node retention knobs (max age / max size / rotate count / compress)
  to a logrotate config and runs it in-container.

## Option A — bind-mount a host mount (recommended for rootless podman)

Mount the share on the host with your usual tooling (`/etc/fstab`, autofs,
systemd mount units), then bind it into the container:

```yaml
services:
  syslog-valve:
    environment:
      YARD_SHARES: "archive"
    volumes:
      - valve-data:/data
      - /mnt/nas/syslog:/shares/archive
```

Why recommended: rootless podman cannot mount NFS/CIFS itself (mounting
needs privileges the user namespace doesn't have), host mounts are visible
to your monitoring, and credentials stay in root-owned host config instead
of compose files.

Mind ownership: rootless containers write as a mapped UID. If the NAS
export squashes or enforces UIDs, make the export writable by the UID the
container runs as (check with `podman unshare ls -ln /mnt/nas/syslog`).

## Option B — compose named volume with NFS driver_opts

Docker (and rootful podman) can mount NFS directly through the `local`
volume driver:

```yaml
volumes:
  logshare-nfs:
    driver: local
    driver_opts:
      type: nfs
      o: addr=nas.example.lan,rw,nfsvers=4
      device: ":/export/syslog"

services:
  syslog-valve:
    environment:
      YARD_SHARES: "archive"
    volumes:
      - logshare-nfs:/shares/archive
```

The mount happens lazily on first container start; a wrong `addr`/`device`
surfaces as a container start error, not a compose validation error.

## Option C — compose named volume with CIFS/SMB driver_opts

```yaml
volumes:
  logshare-smb:
    driver: local
    driver_opts:
      type: cifs
      o: username=svc-syslog,password=…,uid=0,file_mode=0660,dir_mode=0770
      device: "//nas.example.lan/syslog"
```

Prefer a dedicated low-privilege NAS account. The credentials end up in the
compose file and in `docker volume inspect`; if that bothers you (it
should), use Option A with a root-owned `/etc/fstab` credentials file
instead.

## Retention semantics on shares

- **Rotation**: the valve's generated logrotate config always uses
  `copytruncate`, so syslog-ng's open file descriptor keeps working across
  rotation — no signal/reopen coordination with the NAS required. The
  trade-off is inherent to copytruncate: a small window where messages
  written between copy and truncate can be lost. At yard traffic rates this
  is acceptable; if it isn't for you, cache locally and archive off-band.
- **NFS**: compression during rotation is fine. Use `nfsvers=4`; with NFSv3
  make sure locking (statd) works or rotation can hang.
- **CIFS/SMB**: file locking is the classic logrotate trap — `copytruncate`
  (already the default here) avoids the rename-while-open failure mode.
  Expect `compress` to be slower over SMB; consider switching it off on
  high-volume cache nodes.
- **Disk-full behaves like local disk-full**: syslog-ng drops or blocks per
  its destination settings. Size-based retention (`max size`) is the knob
  that keeps a share from filling.

## Verifying a share

After `yardctl up`, the valve logs each accepted share at startup
(`share "archive": /shares/archive`) and skipped ones with the reason. In
the valve UI, a cache node's **location** picker lists local `/data` plus
every accepted share. Apply a flow that caches to the share, then check a
file appears: `docker compose -f deploy/compose.yaml exec syslog-valve ls
/shares/archive`.
