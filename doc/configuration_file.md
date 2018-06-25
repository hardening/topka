# Introduction

# Sample configuration file

```python
import hashlib
import aaa.auth.local_db

globalConfig = {    
    'authMethod': aaa.auth.local_db.FileDb('/etc/topka/passwd.db', hashlib.sha1),
}

thrift = {
    'certPath': '/etc/topka/certs/ots.crt',
    'keyPath': '/etc/topka/certs/ots.key',
}
              
ogon = {
    "ssl.key": "/etc/topka/certs/rdp-server.key",
    "ssl.certificate": "/etc/topka/certs/rdp-server.crt",       
}


applications = {
    'greeterApp': {
        'template': 'qt',
        'path': '/opt/ogon/bin/greeter',
        'user': 'nobody',
    },
    
    'desktopApp': {
        'template': 'weston',
        'path': '/opt/ogon/bin/weston',
        'user': '${user}',
    }
}

greeter = 'greeterApp'
desktop = 'desktopApp'
```

# Reference Manual

## `globalConfig`

The `globalConfig` entry contains some global parameters.

### `pipesDirectory`
The directory where ogon pipes will be stored. Defaults to `/tmp/.pipe`.

### `ld_library_path`
The global `LD_LIBRARY_PATH` that will be set to all programs launched by topka. Defaults to `[]`.

### `pipeTimeout`
The delay to wait for pipes to be created by content providers. Defaults to `10 seconds`.

### `pipeSchema`
The schema of created pipes. Defaults to `ogon_{sessionId}_{appName}`.

### `xdg_runtime_schema`
The schema for the `XDG_RUNTIME` directory that may be created by topka (to comply to the XDG specifications). Defaults to `/run/user/{runAsUserId}`.

### `user_default_path`
The `PATH` to set when launching programs. Defaults to `['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin']`
        
### `tokenFileTemplate`
The schema for OTS token files. Defaults to `/tmp/ogon.session.{0}`. Change this value only if you know what you're doing (usually that
you're writing your own OTS library), as the ogon ots library expect that format.
        
### `authProvider`
An instance of `AuthenticationProvider` that will perform user authentications. Defaults to `aaa.auth.NoProvider()`, a provider that always say "no".

### `userMapper`
An instance of  `auth.usermapper.IdentityUserMapper` that will map remote users to a local one. Defaults to `aaa.usermapper.IdentityUserMapper()`, a mapper that
will use the same local account as the remote login.
       
### `policyProvider`
An instance of `auth.userpolicy.UserPolicyProvider` that will return a user policy (maximum resolution, maximum number of monitors, session uniqueness, ...). Defaults to `aaa.userpolicy.UserPolicyProvider()` a 
    

## `icp`

The `icp` entry contains some parameters specific to the ICP part (link between topka and the ogon server) of topka. 

### `listeningPipe`
The name of the pipe to listen on for ICP connections. Defaults to `ogon_SessionManager`, don't change this value unless you know what you're doing (most
probably if you're writing your own ogon server), as ogon expect that pipe.

### `mode`
The file attributes to set on the ICP pipe. Defaults to `0666`.
    
    
## `thrift`

### `certPath`
The certificate file to use for incoming OTS (through thrift) connection. Defaults to `server.crt`.

### `keyPath`
The key file to use for incoming OTS (through thrift) connection. Defaults to `server.key`.
        
### `bindAddr`
The address to listen on for OTS connexions. Defaults to `tcp://127.0.0.1:9091`.


## `ogon`

The `ogon` entry contains some parameters specific to the RDP of topka. 


### `ssl.key`
The path to the SSL key file when the client uses RDP4 or TLS security.

### `ssl.certificate`
The path to the SSL cert file when TLS security is used.

### `forceWeakRdpKey`
A boolean indicating if we should generate some weak RSA keys to use with old clients that don't support keys higher than 1024 bits. Defaults to `False` (secure option).
        
### `showDebugInfo`
A boolean indicating if ogon should draw a debug bar that will show the state of the ogon server (codec used, rate, state, ...) on client's connections. Defaults to `False`.
       
### `disableGraphicsPipeline`
A boolean indicating if ogon should disable (and so not announce it) its `egfx` channel. Defaults to `False`.
        
### `disableGraphicsPipelineH264`
A boolean indicating if ogon should disable (and so not try to use it) the H264 encoding. Defaults to `False`. Please note that the `openH264` library must be present to
have H264 support.
        
### `bitrate`
The bitrate to use with H264 encoding. Defaults to `20`.


## `backendsConfig`

The `backendsConfig` entry contains some parameters specific to each backend. 

### common settings 

* `initialGeometry`: the geometry to use by default when the backend is launched (should change as soon as a peer connects). Defaults to `800x600`;


### static


### qt

#### `pluginsPath`
The path where to find QPA plugins. Defaults to `None`.
                      
## `weston`

#### `serverPath`
The path to the weston binary. Defaults to `None`.
    
### `x11`

#### `depth`
The depth to use on the Xorg server. Defaults to `24`.

#### `serverPath`
The path to the X server. Defaults to `None`

#### `wmPath`
The path of the window manage to launch when the X server is running. Defaults to `None`.

    
## `applications`

This is a list of defined applications

* `type`: the kind of backend to launch
* `directory`: the directory where to launch the application;
* `user`: launch the application using this identity

```json
    'greeter': {
            'type': 'qt',
            'path': None,
            'user': None,
        },
        
        'desktop': {
            'type': 'weston',
            'path': None,
            'user': '${user}',
        }
    },
```

## `greeter`
The name of the application to use for the greeter (when topka figure that you should authenticate).

## `desktop`
The name of the application to use for the desktop (when topka figure that you should authenticate).
