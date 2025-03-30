
FROM maven:3.9-eclipse-temurin-21-alpine AS build

WORKDIR /app


COPY pom.xml .

RUN mvn dependency:go-offline -B


COPY src ./src
RUN mvn package -DskipTests -Dmaven.test.skip=true --no-transfer-progress


FROM eclipse-temurin:21-jre-alpine AS runtime

WORKDIR /app


COPY --from=build /app/target/*.jar app.jar


RUN \
    addgroup -S spring && \
    adduser -S spring -G spring && \
    chown spring:spring /app
USER spring

# 6. Variables de entorno configurables
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75"
EXPOSE 8080

ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} -jar /app/app.jar"]