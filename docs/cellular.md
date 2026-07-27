# Covering cellular

[setup-wireguard.sh](setup-wireguard.sh) leaves you with a tunnel that works at
home. The QR code it prints points at the Pi's address on your own network, and
that address means nothing once the phone is on 4G.

To cover cellular, one thing has to become true: **the phone must be able to
find and reach the Pi from outside your house.** Everything below is in service
of that.

The reward is worth the fiddling. On the home network you are watching a phone
that is mostly idle and on wifi. On cellular you are watching it do what it
actually does all day.

## First: can you do this at all?

Some connections cannot accept an incoming one, no matter how you configure
them. Check before you spend an evening on it.

Find the address your router thinks it has on its internet side — it will be on
the router's status page, labelled WAN or Internet. Then, from any machine on
your network:

```bash
curl -s https://api.ipify.org; echo
```

That is the address the world sees. Compare the two.

**If they match**, you have a real public address. Go to *Path A*.

**If they differ**, your ISP has put you behind carrier-grade NAT: you are
sharing one public address with other customers and nothing can be forwarded to
you. The giveaway is a WAN address starting `100.64.` to `100.127.`, but any
mismatch means the same thing. Go to *Path B*.

Common with mobile broadband, Starlink, and some fibre providers. Many ISPs
will give you a real address for free or a small fee if you ask — worth a phone
call before working around it.

## Path A — a name and an open door

Two things are missing: a name that follows your address when it changes, and a
door in the router.

### 1. Give the Pi a fixed address on your network

Do this first. Port forwarding points at an address, so if the Pi's address
changes on its next lease the forward quietly stops working and nothing tells
you.

Set a DHCP reservation on your router for the Pi's MAC address. Most routers
call it "DHCP reservation", "static lease", or "address reservation".

### 2. Get a name that tracks your address

Home connections usually get an address that changes. Dynamic DNS gives you a
name that follows it.

[DuckDNS](https://www.duckdns.org) is free and takes about five minutes: sign
in, pick a name, and it gives you a one-line updater to run on the Pi from
cron. If you own a domain, Cloudflare's API does the same job.

Check your router first — many have a dynamic DNS client built in, which is
tidier because the router always knows its own address.

You end up with something like `yourname.duckdns.org`.

### 3. Open UDP 51820

In the router, forward **UDP** port 51820 to the Pi's fixed address. Not TCP —
WireGuard is UDP only, and forwarding TCP does nothing at all.

If your router insists on a range, use 51820 to 51820.

### 4. Re-issue the phone's config

Back on the Pi:

```bash
sudo ./docs/setup-wireguard.sh --qr-only --endpoint yourname.duckdns.org
```

This only rewrites the phone's config and prints a new QR code. It does not
touch the keys, so the Pi needs no restart — the tunnel is the same tunnel,
told to look somewhere new.

In the WireGuard app, delete the old tunnel and scan the new code.

## Path B — behind CGNAT

You cannot open a door in a router you do not control. Instead of having the
phone connect *in*, use a service where both ends connect *out* and are
introduced to each other.

[Tailscale](https://tailscale.com) is built on WireGuard, has a free tier that
covers this comfortably, and has an App Store app. It solves CGNAT as a matter
of course.

On the Pi:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --advertise-exit-node
```

Then approve the exit node in the Tailscale admin console, install Tailscale on
the phone, sign in, and pick the Pi as its exit node. That routes all the
phone's traffic through the Pi exactly as WireGuard would.

You still need IP forwarding enabled, which `setup-wireguard.sh` does. You do
not need the WireGuard tunnel, the port forward, or the dynamic DNS — Tailscale
handles its own NAT when acting as an exit node.

**Two things change for crowsnest.** The traffic now arrives on a different
interface, and the phone has a different address:

```bash
sudo tailscale status                    # find the phone's 100.x address
sudo crowsnest live -i tailscale0 --me 100.x.y.z
```

Blocking is unchanged — `--gateway` works the same, because the rules sit on
the forward chain and do not care which interface the traffic arrived on:

```bash
sudo crowsnest block <host> --gateway --client 100.x.y.z --dry-run
```

The trade is that Tailscale's coordination service knows which devices you
have and when they connect. Your traffic still goes directly between phone and
Pi where the network allows it, but that is a real third party in a design that
otherwise had none. On a connection you cannot forward through, it is the price
of the thing working at all.

## Testing it properly

The mistake is testing on wifi, where it works because it was already working.

1. On the phone, **turn wifi off**. Confirm it is on cellular.
2. Turn the tunnel on in the WireGuard app.
3. Load any website.
4. On the Pi:

```bash
sudo wg show
```

Look for `latest handshake` with a recent time. That is proof the phone reached
the Pi from outside. No handshake means the phone never got through — the port
forward or the name is wrong.

Then watch it properly:

```bash
sudo crowsnest live -i wg0 --me 10.6.0.2
```

Lock the phone, put it down, and leave it ten minutes. What appears is the
interesting part — everything your phone talks to when you are not using it.

## When it half-works

**Some sites load, others hang forever.** Almost always MTU. The tunnel adds a
header, so a full-size packet no longer fits, and on some cellular networks the
"too big" message that would normally sort this out never arrives. Symptom is
small pages working and large ones stalling.

```bash
sudo ./docs/setup-wireguard.sh --qr-only --endpoint yourname.duckdns.org --mtu 1280
```

1280 is the safe floor for IPv6 and works essentially everywhere. Re-scan.

**Works, then stops after a few minutes idle.** The carrier dropped the NAT
mapping. `PersistentKeepalive = 25` is already in the generated config to
prevent this; check it survived any hand-editing.

**Nothing at all on cellular, fine on wifi.** The port forward is not working.
Confirm the name resolves from outside — check on the phone with wifi off,
using any DNS lookup app, or ask someone else to try. Also confirm you
forwarded UDP and not TCP.

**The Pi goes down while you are out.** The phone has no internet until you
turn the tunnel off in the WireGuard app. Worth knowing before it happens
rather than during it.

## What you are accepting

**Your phone's traffic now exits from your home connection.** Websites see your
home address, and your home ISP sees your phone's traffic — including
everything it does on cellular, which it never saw before. You are not removing
a party who can watch; you are moving from your mobile carrier to your home
ISP. That may well be what you want, but it is a change of who, not a removal.

**The open port is less alarming than it looks.** WireGuard does not reply to
packets it cannot authenticate — a scan of UDP 51820 gets silence, exactly as
if nothing were listening. It cannot be identified or fingerprinted from
outside. Do keep the Pi patched, and do not forward SSH as well: once the
tunnel is up you can reach the Pi over it, which is strictly better than
exposing port 22.

**Battery.** An always-on tunnel with a keepalive every 25 seconds is a real
cost, though a modest one — WireGuard is far lighter than older VPN protocols.

**One device.** This covers the phone whose config you scanned. Others need
their own peer.
