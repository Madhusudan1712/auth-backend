#---- Build Stage ----
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

#---- Runtime Stage ----
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
ENV JAVA_TOOL_OPTIONS="-Djava.net.preferIPv4Stack=true -Djava.net.preferIPv6Addresses=false -Dsun.net.inetaddr.ttl=60 -Dsun.net.inetaddr.negative.ttl=0 -XX:MaxRAMPercentage=75.0"
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]