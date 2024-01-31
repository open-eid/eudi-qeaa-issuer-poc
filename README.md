<img src="src/main/resources/static/potential_logo.png" alt="Potential. For European Digital Identity. Co-funded by the European Union."  style="width: 400px;"/>
Funded by the European Union. Views and opinions expressed are however those of the author(s) only and do not 
necessarily reflect those of the European Union or Potential Consortium. Neither the European Union nor the granting 
authority can be held responsible for them.

# EUDI QEAA Issuer POC

## Documentation

- [open-eid/eudi-qeaa-doc](https://github.com/open-eid/eudi-qeaa-doc)

## Running

1. Checkout companion projects
    - [open-eid/eudi-qeaa-as-mock](https://github.com/open-eid/eudi-qeaa-as-mock)
    - [open-eid/eudi-qeaa-rp-mock](https://github.com/open-eid/eudi-qeaa-rp-mock)
    - [open-eid/eudi-qeaa-rp-backend-mock](https://github.com/open-eid/eudi-qeaa-rp-backend-mock)
    - [open-eid/eudi-qeaa-wallet-mock](https://github.com/open-eid/eudi-qeaa-wallet-mock)

2. Build Docker image for each project (including current)

Either build locally

```shell
./mvnw spring-boot:build-image
```

Or build in Docker

Windows Powershell
```shell
docker run --pull always --rm \
       -v /var/run/docker.sock:/var/run/docker.sock \
       -v "${env:USERPROFILE}\.m2:/root/.m2" \
       -v "${PWD}:/usr/src/project" \
       -w /usr/src/project \
       maven:3.9-eclipse-temurin-21 \
       mvn spring-boot:build-image -DskipTests
```
Linux
```shell
docker run --pull always --rm \
       -v /var/run/docker.sock:/var/run/docker.sock \
       -v "$HOME/.m2:/root/.m2" \
       -v "$PWD:/usr/src/project" \
       -w /usr/src/project \
       maven:3.9-eclipse-temurin-21 \
       mvn spring-boot:build-image -DskipTests
```

3. Generate required resources

```shell
cd ./local
./generate-resources.sh
```

4. Run in Docker

```shell
docker compose up
```

5. Test Issuance flow
- https://eudi-wallet.localhost:16443/

6. Test Presentation flow
- https://eudi-rp.localhost:14443/
