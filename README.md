an ephemeral messaging protocol. modules in this repository are standard implementations for the server, the client, and shared functionality.

refer to:
- [guidance records (doesn't match this page yet)](./src/shared/mod.rs)
- [standard server & db implementation (doesn't work yet)](./src/server/stdimpl.rs)

# philosophy:
neither the client nor server must rely on any third parties, and both server/client software must be as easy to host as possible, with no cost attached. this implies:
- no third party TLS certificates
- the network is intended to be federated and hosted by small groups of people
- one server may not hold more power than another
- the message format is strict and standardized for each version, and once, maturity is achieved, has to be backwards-compatible
- registration is handled by the administrator
- a server could change its IP at any time and may even be viable to host on a dynamic IP
- (in the future) a modular composition, refer to the bottom of the page 

# protocol:
any message can be sent between an anonymous user (a), a server (s), and an authenticated user (u). later, the connections are referred to as a2s, u2s, s2s, etc...

response example:
```
lung/a0.1 status 0: teapot status # protocol version and status
ok: true # a header
length: 34 # anything with body must include a length header

hello! this is an example response # body, in this case just utf-8
```
the headline could also look like `lung/a0.1 0` in future versions
it should just parse the version until the first space and then look for an integer

request example:
```
lung/a0.1 send
to: user#server
session: token
length: 2

yo
```
fine specimen right? there's a good reason the length is attached: whatever's in the body is up to user#server's interpretation. your only expectation is not exceeding the server's max-length (see the info request)

### certificates
usually, the certificates are done via third-party authorities. it's a great model because you can't mitm the psk. but third-party authorities are a big no-no, so the first request to a server is made unencrypted and all subsequent communication has to be encrypted via (rsa?)

### message exchange
messages could be exchanged as u2s2s2u (on different servers), u2s2u (on the same server), or a2s2u (sealed message)

### friend servers
a server will have a list of usually 8-16 trusted friends. they have 2-way encryption and could act as proxies

anyone whos on s1 is gonna request s1's list of friends

### IP changes:
- for users:
a user could change their id at any time by sending a request to their parent's server or a parent server's friend server
- for servers:
servers could die and go back up at any time, but it should not be.

an IP change is broadcasted via an a2s request

## contact flow example
### certificate request
a certificate request is the only non-encrypted request you can have
-> client:
```
lung/a0.1 certificate
```
<- server:
```
lung/a0.1 status 50: certificate given
algo: x25519
pubkey: [server's pubkey]
```
client stores server_pub

### send message
the session body is none of the server's business, it can be encrypted with anything, it's just an array of bytes

-> client:
```
lung/a0.1 send
to: bobby#s1
session: [token]
length: 2

yo # it's the user's responsibility to encrypt their messages
```
<- server:
```
lung/a0.1 status 1: message sent
ok: true
timestamp: [unix timestamp]
message-id: [uuid v4]
```

then comes the message relay

s1 -> s2:
```
lung/a0.1 deliver
from: jerma#s1
to: bobby#s2
sig: SIGN(server1_priv, message_id)
timestamp: [original unix timestamp]
message-id: [uuid v4]
body-hash: SHA256(base64(body))

yo # it's the user's responsibility to encrypt their messages
```
if s2 has a socket open with bobby it just gives them the message signed by the u2s key. if not, it's stored in a queue

### sealed message
a sealed message lets an anonymous user (a1) to send a message directly to an authenticated user (u2) without the server knowing a1's identity or message contents.

a1 -> s2:
```
lung/a0.1 sealed
to: u2
length: [blob length]
encrypted: true

[blob encrypted with u2's pubkey]
```
or
```
lung/a0.1 sealed
to: u2
length: [blob length]
encrypted: false

[plaintext blob]
```

the user then receives the message and, if it's encrypted, goes on to match it to their listed user-privkey pairs. if none work, the message is lost

### hash auth
> the token is a string of `client [name]#[server] until [unix timestamp]` 

-> client:
```
lung/a0.1 hash auth
client: jerma
hash: SHA256(password+":"+server_nonce)
```
<- server:

- success:
    ```
    lung/a0.1 status 60: hash accepted
    ok: true
    session: [token]
    until: UNIX_TIMESTAMP(1 week from now)
    ```
- failure:
    ```
    lung/a0.1 status -60: hash not accepted
    ```

all u2s requests use the session header now

if you see you're running out, you just request a new one via the same endpoint

### message retrieval
-> client:
```
lung/a0.1 anything?
session: [token]
```
<- server
```
lung/a0.1 status 5: offline messages
count: 2

timestamp: [unix timestamp]
from: bobby#s1
length: 3

yo

timestamp: [unix timestamp]
from: bobby#s1
length: 3 #this is why length is included

aasdfasdfasd f\n\n\n\n\ntimestamp: 1\nfrom: bobby#example\nlength: 123123\nrekt


timestamp: [unix timestamp]
from: !plain_sealed # all usernames starting with a bang are special use
length: 2

yo


timestamp: [unix timestamp]
from: !sealed # all usernames starting with a bang are special use
length: usize

[sealed message]
```

### friend system
servers may establish trusted links called friends to route messages, share notifications and for key exchange

they're two-way and signed, each server stores a local list of friends. they're equal peers with ho hierarchy

- friend records:
    each server has a friend record, which is a signed blob blob with its identity and reachable addresses
    ```yaml
    a0.1 lung data: friend-record
    server: s1
    pubkey: BASE64(ed25519 pubkey)
    addrs: ["1.2.3.4:1337", "s1.ddns.net:1337"]
    seq: 17 # increments on change
    expires: 1732000000 # unix timestamp, optional ttl
    sig: SIGN(server_priv, SHA256(all above))
    ```
- friend requests:
    to make friends, s1 sends a signed request to s2

    s2 may store those until the admin makes up their mind

    s1 -> s2:
    ```yaml
    lung/a0.1 friend request
    from: s1
    seq: 1
    length: 13
    sig: SIGN(s1_priv, SHA256(body))

    BASE64("pls")
    ```
    s2 -> s1:
    ```
    lung/a0.1 friend made
    record: BASE64({
      server: s2,
      pubkey: BASE64(...),
      addrs: ["1.2.3.4:1337"],
      seq: 3,
      expires: 1732000000
    })
    sig: SIGN(s2_priv, SHA256(record))
    ```
    s1 then verifies the signature and stores s2 as a trusted friend in its "friends" table (the one from the `auth info` request

    it is stored like `{ addr: 1.0.0.0:1337, key: BASE64(key), seq: 17 }`

    the sequence int is a monotonic version counter. every time a friend refreshes a friend record, it is not overwritten, but an old record is removed and a new one with the next seq number is added

    to finalize, s1 mirrors the friend made back

    s1 -> s2
    ```
    lung/a0.1 friend made
    record: BASE64(friend-record of s1)
    sig: SIGN(s1_priv, SHA256(record))
    ```
- friend revocation:
    if s2 for some reason becomes untrusted, a notification is published
    ```
    lung/a0.1 friend revoke
    server: s2
    seq: 18
    sig: SIGN(s1_priv, SHA256("revoke:"+server+":"+seq))
    length: 13

    BASE16(compromised)
    ```
    users then request an info and adjust their friend record accordingly

- friend info request:
    any authenticated user may request a signed friend record from a server

    user -> s1
    ```
    lung/a0.1 friend info
    server: s2
    ```
    
    s1 -> user
    ```
    lung/a0.1 status 80: friend record
    record: BASE64(friend-record)
    ```
- verification:
    first contact uses tofu

    server then stores the pubkey and later and verifies that all future signed records match it
- friend types:
    `trusted` - two-way routing & key verification
    `observer` - receives notifications only

### info request
a server's only identification is its key - if messages are signed with it, you can verify its authenticity
-> anon client:
```
0.1 info
```
<- server:
```
0.1 status 4: info given
version: 0.1 # assuming backwards-compatibility
max-length: 64000
signature: ALGO:[signature]
```

it's good to check up on notifications once in a while. you'll update your list of friends and see what the admin has to say

-> authenticated client:
```
0.1 auth info
session: [session]
```
<- server:
```yaml
0.1 status 4: info given
version: 0.1 # assuming backwards-compatibility
max-length: 64000
signature: ALGO:[signature]
friends: [
    { addr: 1.0.0.0:1337, key: BASE64(pubkey), seq: 17 },
    { addr: 1.0.0.0:1338, key: BASE64(pubkey), seq: 8 },
]
current-session-valid-until: 1731515023
name: BASE64(jerma's server)
last-mail-timestamp: [unix timestamp]
```
the client then checks what it stores as the last-mail message and then asks the server for offline messages at `!self-[client's last mail]`

### server notification
it should not be difficult at all to change a server's ip

-> anon to server:
```
lung/a0.1 notification
from: [friend id encrypted with a pubkey]
[encrypted with the friend key]
new-ip: 2.0.0.0:1337
OR AND
offline: forever/unix timestamp
OR AND
forget: please
OR AND
```
anyone willing could easily send junk here twice/once a day at utc 0 or utc 12 for hygiene to obscure meaningful notifications to anyone in the middle. if an actual person wants to do it, they'll know sending it at utc 0 is safest

then a client may try to reach 1.0.0.0 but it can't find it. they'll have stored the server's friends and exchanged keys with them prior so

-> client to friend 1-16 until success:
```
lung/a0.1 anyone
at: 1.0.0.0:1337
```

<- friend:
- success:
    ```
    lung/a0.1 status 70: notification found
    type: moved
    elaboration: 2.0.0.0:1337
    OR
    type: gone
    elaboration: forever/unix timestamp
    ```
- failure:
    ```
    lung/a0.1 status -70: notification not found
    ```
### user notification
a user may want to change their id, too. they would make a request to their parent server's friend server

-> jerma#server5 to s1's friend server:
```
lung/a0.1 user notification
client: jerma
type: moved
to: jerma#server5
```

### long lived connections
an authenticated user may request a long-lived one-directional connection. everything that should end up in the offline request queue will be emptied onto the socket instead

## encryption
idk

# future maybes
- exchanging pubkeys through friend servers
- servers with groupchats that have channels which could be hosted on the same machine as a normal communication server
- change true/false to y/n for no reason
- public server rings/listings
- turn the whole thing into a modular system
    servers will be purely nodes for authentication and communication, data storage and sending arbitrary data back and forth, but the rest will be a composition of modules
    examples:
        - lung-message-transfer@0.1, for message transfer. spec request will yield a documentation for how you'd make requests of `lung/a0.1 mod/lms\nto: recipient`
        - lung-public-feed@0.1, for public feeds. spec request will yield a documentation for how you'd make requests of `lung/a0.1 mod/lpf \n user: jerma#s1 \n page: 0 \n count: 15`
    this could let admins to fix any behaviour they don't like, or add their own, relying on the core architecture
