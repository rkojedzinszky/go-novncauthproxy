FROM scratch

LABEL maintainer="Richard Kojedzinszky <richard@kojedz.in>"

ADD go-novncauthproxy /

EXPOSE 8080

USER 5900

CMD ["/go-novncauthproxy"]
