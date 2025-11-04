# ---------------------------------
# 1. 빌드(Build) 단계
# ---------------------------------
# Gradle(JDK 17 포함) 이미지를 'builder'라는 이름으로 사용
# (프로젝트의 Java 버전에 맞게 11, 17, 21 등으로 수정)
FROM gradle:8.14.3-jdk21 AS builder

# 빌드 환경에 Node.js(npm) 설치
# (프로젝트의 Node.js 버전에 맞게 16.x, 18.x 등으로 수정)
RUN apt-get update && \
    apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_10.9.3 | bash - && \
    apt-get install -y nodejs

WORKDIR /workspace

# Gradle 캐시를 활용하기 위해 빌드 파일 먼저 복사
COPY build.gradle settings.gradle gradlew ./
COPY .gradle ./.gradle

# 전체 프로젝트 소스 코드 복사
COPY . .

# Gradle 실행 권한 부여 및 빌드 실행
# 이 명령어 하나가 React 설치, React 빌드, Spring 빌드를 모두 처리합니다.
RUN chmod +x ./gradlew
RUN ./gradlew build -x test

# ---------------------------------
# 2. 실행(Runtime) 단계
# ---------------------------------
FROM openjdk:21-jre-slim

WORKDIR /app

# 'builder' 단계에서 생성된 최종 .jar 파일을 복사
COPY --from=builder /workspace/build/libs/*.jar app.jar

# 컨테이너가 노출할 포트 (스프링 부트 기본 포트 8080)
EXPOSE 8080

# 컨테이너가 시작될 때 실행할 명령어
ENTRYPOINT ["java", "-jar", "app.jar"]