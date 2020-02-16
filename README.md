# go-novncauthproxy

A novnc proxy inspired on [snf-vncauthproxy](https://github.com/grnet/snf-vncauthproxy), but handles VNC connections over Websocket only. The target host/password is encoded in a JWE token, which is passed in the URI.
Thus, multiple instances can be run (e.g. in Kubernetes).

# Usage

## Plain

```
./go-novncauthproxy -jwe-secret=lz2jVFPT36rk3Vak11dTSNRBQ0NEH/0sYt3Q2yVOnI4=
```

The secret key is a 256 bit (32 byte) key, encoded in base64. One can be generated as:
```
$ dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64
VyA/BvPHJTJEt2EZv3PVPuM4xEXFL+dS5KCOiWKz4MM=
```

## Containerized

All flags can be passed as environment variables, so running with Docker is easy too:
```
$ docker run -it --rm -e JWE_SECRET=lz2jVFPT36rk3Vak11dTSNRBQ0NEH/0sYt3Q2yVOnI4= -p 8080:8080 rkojedzinszky/go-novncauthproxy
```

## Kubernetes

See example [deployments](deploy/kubernetes).

# Operation

Then the proxy listens on plain http on `:8080` by default, expects the JWE token passed at `/novnc/<token>` with no slash at the end. Then, it parses the token, checks its expiry, and extracts VNC connection details from claims. For generating a sample token, see [encode.py](tools/encode.py). Then, you can use that token on [novnc demo](https://novnc.com/noVNC/vnc.html) for testing purposes.

# Applications

Right now, a forked [ganetimgr](https://github.com/rkojedzinszky/ganetimgr/tree/novnc-jwe) is using it.