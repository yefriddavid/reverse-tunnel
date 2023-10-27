



# Reverse proxy
/etc/ssh/sshd_config

```

ssh -R 8080:127.0.0.1:8080 operatore@146.148.22.123

Match User ubuntu
    GatewayPorts       yes
    AllowTcpForwarding remote
    PermitOpen         127.0.0.1:8083

```

## Refereences
- https://gist.github.com/codref/473351a24a3ef90162cf10857fac0ff3
- https://github.com/goreleaser/goreleaser/blob/main/Taskfile.yml
