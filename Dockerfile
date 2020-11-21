FROM scratch

LABEL org.opencontainers.image.authors "Richard Kojedzinszky <richard@kojedz.in>"
LABEL org.opencontainers.image.source https://github.com/rkojedzinszky/go-novncauthproxy

ADD go-novncauthproxy /

EXPOSE 8080

USER 5900

CMD ["/go-novncauthproxy"]
