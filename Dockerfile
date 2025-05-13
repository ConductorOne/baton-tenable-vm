FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-tenable-vm"]
COPY baton-tenable-vm /