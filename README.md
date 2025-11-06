> this is heavily WIP!! feel free to make any suggestions in issues or pull requests

an ephemerality-focused messaging protocol. modules in this repository are standard implementations for the server, the client, and shared functionality.

refer to:
- [guidance records](./src/shared/mod.rs)
- [standard server & db implementation (doesn't work yet)](./src/server/stdimpl.rs)

# philosophy:
neither the client nor server must rely on any third parties, and both server/client software must be as easy to host as possible, with no cost attached. this implies:
- no third party TLS certificates
- the network is intended to be federated and hosted by small groups of people
- one server may not hold more power than another
- the message format is strict and standardized for each version, and once, maturity is achieved, has to be backwards-compatible
- registration is handled by the administrator
- a server could change its IP at any time and may even be viable to host on a dynamic IP

# protocol:
any message can be sent between an anonymous user (a), a server (s), and an authenticated user (u). later, the connections are referred to as a2s, u2s, s2s, etc...

response example:
```
wl/a0.1 status 0: teapot status // protocol version and status
ok: true // a header
length: 34 // anything with body must include a length header

hello! this is an example response // body, in this case just utf-8
```
the headline could also look like `wl/a0.1 0` in future versions
it should just parse the version until the first space and then look for an integer

request example:
```
wl/a0.1 send
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

- u2s2s2u:
>  

### friend servers
a server will have a list of usually 8-16 trusted friends. they have 2-way encryption and could act as proxies

anyone whos on s1 is gonna request s1's list of friends

### IP changes:
- for users:
- for servers:
servers could die and go back up at any time, but it should not be.

an IP change is broadcasted via an a2s request

## contact flow example
### certificate request
a certificate request is the only non-encrypted request you can have
-> client:
```
wl/a0.1 certificate
```
<- server:
```
wl/a0.1 status 50: certificate given
algo: x25519
pubkey: [server's pubkey]
```
client stores server_pub

### send message
the session body is none of the server's business, it can be encrypted with anything, it's just an array of bytes

-> client:
```
wl/a0.1 send
to: bobby#s1
session: [token]
length: 2

yo // it's the user's responsibility to encrypt their messages
```
<- server:
```
wl/a0.1 status 1: message sent
ok: true
timestamp: [unix timestamp]
message-id: [uuid v4]
```

then comes the message relay

s1 -> s2:
```
wl/a0.1 deliver
from: jebediah#s1
to: bobby#s2
sig: SIGN(server1_priv, message_id)
timestamp: [original unix timestamp]
message-id: [uuid v4]
body-hash: SHA256(base64(body))

yo // it's the user's responsibility to encrypt their messages
```
if s2 has a socket open with bobby it just gives them the message signed by the u2s key. if not, it's stored in a queue

### sealed message
a sealed message lets an anonymous user (a1) to send a message directly to an authenticated user (u2) without the server knowing a1's identity or message contents.

a1 -> s2:
```
wl/a0.1 sealed
to: u2
length: [blob length]
encrypted: true

[blob encrypted with u2's pubkey]
```
or
```
wl/a0.1 sealed
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
wl/a0.1 hash auth
client: jebediah
hash: SHA256(password+":"+server_nonce)
```
<- server:

- success:
    ```
    wl/a0.1 status 60: hash accepted
    ok: true
    session: [token]
    until: UNIX_TIMESTAMP(1 week from now)
    ```
- failure:
    ```
    wl/a0.1 status -60: hash not accepted
    ```

all u2s requests use the session header now

if you see you're running out, you just request a new one via the same endpoint

### message retrieval
-> client:
```
wl/a0.1 anything?
session: [token]
```
<- server
```
wl/a0.1 status 5: offline messages
count: 2

timestamp: [unix timestamp]
from: bobby#s1
length: 3

yo

timestamp: [unix timestamp]
from: bobby#s1
length: 3 //this is why length is included

aasdfasdfasd f\n\n\n\n\ntimestamp: 1\nfrom: bobby#example\nlength: 123123\nrekt


timestamp: [unix timestamp]
from: !sealed // all usernames starting with a bang are special use
length: 2

yo
```

### friend system
a server can request another server to be friends and they'll have the option of accepting or not accepting the request

s1 -> s2:
```
wl/a0.1 friend request
message: 13:BASE64(pls) // length-message
```
the server will then store that until the admin decides whether to accept it or not

s1 <- s2:
```
wl/a0.1 friend made
pubkey: [friend pubkey] 
```
s1 checks if they asked and then 

s1 -> s2:
```
wl/a0.1 friend made
pubkey: [friend pubkey]
```

### info request
a client may want to know how to use a certain server
-> anon client:
```
0.1 info
```
<- server:
```
0.1 status 4: info given
max-length: 64000
version: 0.1 // assuming backwards-compatibility
```

it's good to check up on announcements once in a while. you'll update your list of friends and see what the admin has to say

-> authenticated client:
```
0.1 auth info
session: [session]
```
<- server:
```
0.1 status 4: info given
max-length: 64000
friends: [
    { addr: 1.0.0.0:1337, key: BASE64(your key) },
    { addr: 1.0.0.0:1338, key: BASE64(your key) },
]
current-session-valid-until: 1731515023
name: BASE64(jebediah's server)
last-mail-timestamp: [unix timestamp]
```
the client then checks what it stores as the last-mail message and then asks the server for offline messages at `!self-[client's last mail]`

### ip announcement
it should not be difficult at all to change a server's ip

-> anon to server:
```
wl/a0.1 announcement
from: [friend id encrypted with a pubkey]
[encrypted with the friend key]
new-ip: 2.0.0.0:1337
OR AND
offline: forever/unix timestamp
OR AND
forget: please
OR AND
```
anyone willing could easily send junk here twice/once a day at utc 0 or utc 12 for hygiene to obscure meaningful announcements to anyone in the middle. if an actual person wants to do it, they'll know sending it at utc 0 is safest

<- server to anon:
```
0.1 status 0: teapot // acknowledged
```

then a client may try to reach 1.0.0.0 but it can't find it. they'll have stored the server's friends and exchanged keys with them prior so

-> client to friend 1-16 until success:
```
wl/a0.1 anyone
at: 1.0.0.0:1337
```

<- friend:
- success:
    ```
    wl/a0.1 status 70: announcement found
    type: moved
    elaboration: 2.0.0.0:1337
    OR
    type: gone
    elaboration: forever/unix timestamp
    ```
- failure:
    ```
    wl/a0.1 status -70: announcement not found
    ```

# future maybes
- exchanging pubkeys through friends
- servers with groupchats that have channels which could be hosted on the same machine as a normal communication server
