env GOOS=linux GOARCH=arm GOARM=5 go build -o traefik-cert-extractor  main.go 
upx traefik-cert-extractor