> probably not gonna be done in the near future

an admin may want to rely on the federated nature of the project, but the feature set should not be limited to just what's provided. here's an outline of how modules may be used

the core would have to be minimal and stable, and the modules will be given the ability to be minimal and stable

# separation of concerns
- core: parsing, sessions, friend list, key management, request queues, transport, storage API, module loader
- module: independent binary/library exposing a small RPC surface to the core. modules do not bypass core auth/signing/storage APIs

## module file structure
this is the file structure including the below module
```
lung # executable
lung.toml # maybe lua in the future
modules/
    lung-message-transfer/
        manifest.yaml
        mod # executable
```

## module manifest:
they'll just be somewhere in the configuration
> the yaml format is not final!
```yaml
id: stories
version: a0.1
entry: ./mod
data: persistent
communication: stdout # or unix-socket
capabilities:
    - post:
        type: u2s # authenticated
        required_headers: [session]
        body: binary
        # the rest of the fields are implied to be none/empty
    - list:
        type: f2s # authenticated foreigner to server, through their server
        required_headers: [client]
    - get:
        type: f2s  
        required_headers: [client]
deps: []
config-schema:
    max_queue_size: {type: int, default: 10000}
```

then it can be included in the config like this
```yaml
name: jerma's server
max-length: 1mb
modules:
    lmt:
        max_queue_size: 10000

```
## module's actions
a module will expose a set of actions defined in the capabilities field that look like this

user to server:
```
lung/a0.1 !stories/post
session: [token]
```

foreigner to server:
```
lung/a0.1 !stories/get
```
