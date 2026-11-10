# ---- build stage: compile and test with Maven
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -B -ntp -q dependency:go-offline
COPY src ./src
RUN mvn -B -ntp -q verify

# ---- runtime stage: just a JRE and one jar, running as a non-root user
FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S app && adduser -S app -G app
USER app
COPY --from=build /src/target/headerguard.jar /app/headerguard.jar
ENTRYPOINT ["java", "-jar", "/app/headerguard.jar"]
