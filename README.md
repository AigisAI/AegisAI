# AegisAI
[AegisAI 프로젝트 배너 이미지 삽입]
<br/>
<br/>

# 1. Project Overview (프로젝트 개요)
- **프로젝트 이름**: 🛡️ AegisAI
- **프로젝트 설명**: LLM과 AI를 이용한 품질 및 보안 점검 도구 서비스
- **프로젝트 목표**:
    - AI 기반으로 소스 코드의 보안 취약점을 자동으로 탐지
    - 개발자가 즉시 적용할 수 있는 안전한 수정 코드를 제안
    - 수정안에 대한 자연어 가이드를 생성하여 개발자의 이해도 향상

<br/>
<br/>

# 2. Team Members (팀원 및 팀 소개)
| 김성은 | 권태욱 | 이정재 | 황지원 |
|:------:|:------:|:------:|:------:|
| [Backend] | [Backend] | [Ai/Data] | [Frontend] |
| [GitHub]([https://github.com/링크]) | [GitHub]([https://github.com/goodtu02]) | [GitHub]([https://github.com/링크]) | [GitHub]([https://github.com/링크]) |

<br/>
<br/>

# 3. Key Features (주요 기능)
- **AI 기반 자동 취약점 탐지**:
  - **GraphCodeBERT** 모델을 사용하여 코드의 문맥과 데이터 흐름을 파악하고 취약한 라인을 식별합니다.

- **안전한 코드로 자동 변환**:
  - **CodeT5** 모델이 탐지된 취약 코드를 보안성이 강화된 안전한 코드로 자동 변환하고 수정안을 제안합니다.

- **자연어 설명 가이드 생성**:
  - **Gemini API**를 활용하여, 수정된 코드가 왜 더 안전한지, 어떤 취약점이 해결되었는지 자연어로 설명하여 개발자의 이해를 돕습니다.

- **직관적인 웹 UI 제공**:
  - React + Vite 기반의 프론트엔드를 통해 사용자가 코드를 쉽게 입력하고, 분석 결과를 시각화된 리포트로 확인할 수 있습니다.

- **AI 자동화 파이프라인**:
  - 코드 파싱(Tree-sitter) -> 취약점 탐지(GraphCodeBERT) -> 코드 변환(CodeT5) -> 결과 설명(Gemini)에 이르는 전 과정을 자동화합니다.

<br/>
<br/>

# 4. Tasks & Responsibilities (작업 및 역할 분담)
|  |  |  |
|-----------------|-----------------|-----------------|
| 김성은 | [프로필 사진] | <ul><li>[담당 역할 1, 예: Spring Boot 백엔드 아키텍처 설계]</li><li>[담당 역할 2, 예: API 개발]</li></ul> |
| 권태욱 | [프로필 사진] | <ul><li>[담당 역할 1, 예: Spring Boot 백엔드 아키텍처 설계, 백엔드 API 개발]</li><li>[담당 역할 2, 예: DB(PostgreSQL) 설계]</li></ul> |
| 이정재 | [프로필 사진] | <ul><li>[담당 역할 1, 예: AI 파이프라인 구축, Gemini API 연동]</li><li>[담당 역할 2, 예: GraphCodeBERT/CodeT5 모델 튜닝,분석 결과 시각화 UI/UX 설계]</li></ul> |
| 황지원 | [프로필 사진] | <ul><li>[담당 역할 1, 예: 프론트엔드(React) 개발]</li><li>[담당 역할 2, 예: 분석 결과 시각화 UI/UX 설계]</li><li>[담당 역할 3, 예: 인프라(EC2) 배포]</li></ul> |

<br/>
<br/>

# 5. Technology Stack (기술 스택)
## 5.1 Frontend
| | |
|---|---|
| React | <img src="https://github.com/user-attachments/assets/e3b49dbb-981b-4804-acf9-012c854a2fd2" alt="React" width="100"> |
| Vite | <img src="https://raw.githubusercontent.com/vitejs/vite/main/docs/public/logo.svg" alt="Vite" width="100"> |

*(PDF 기반)*

## 5.2 Backend & Infra
| | |
|---|---|
| Spring Boot | <img src="https://github.com/user-attachments/assets/2e90f331-5f0c-43f1-817d-93d4346808f3" alt="Spring Boot" width="100"> |
| Amazon EC2 | <img src="https://github.com/user-attachments/assets/263f35a0-96b1-4a53-810a-f0f513909c2a" alt="Amazon EC2" width="100"> |
| PostgreSQL | <img src="https://github.com/user-attachments/assets/6b36a87c-c466-4c75-9c59-70ab18d844e3" alt="PostgreSQL" width="100"> |

*(PDF 기반)*

## 5.3 AI
| | |
|---|---|
| PyTorch | <img src="https://github.com/user-attachments/assets/c15b14f8-***-***-***-***" alt="PyTorch" width="100"> |
| TensorFlow | <img src="https://github.com/user-attachments/assets/***-***-***-***-***" alt="TensorFlow" width="100"> |
| **GraphCodeBERT** | (취약점 탐지) |
| **CodeT5** | (코드 변환) |
| **Gemini API** | (자연어 설명) |

*(PDF 기반)*
## 🚀 AI Pipeline & Model Serving

이 프로젝트는 **Hybrid AI Architecture**를 채택하여, 로컬 SLM(Small Language Model)과 클라우드 LLM의 장점을 결합했습니다.

### 1. Model Pipeline (`model_pipeline.py`)
* **Detection:** `CodeBERT`를 사용하여 취약점 유무를 빠르게 분류
* **Auto-fix (Core):** `CodeT5-base` 모델에 보안 데이터셋을 학습시킨 **LoRA Adapter**를 적용하여 코드 수정
* **Explanation:** `Google Gemini Pro`를 연동하여 수정된 이유를 자연어로 설명 (XAI)

### 2. Fine-tuned Models (Hugging Face)
 직접 파인튜닝하여 배포한 모델은 아래 링크에서 확인하실 수 있습니다. (학습 코드는 로컬 환경에 있어 추후 업로드 예정)
* **Vulnerability Fixer (LoRA):** [mangsense/codet5-base-clean-LoRA](https://huggingface.co/mangsense/codet5-base-clean-LoRA)
* **Vulnerability Detector:** [mangsense/codebert_java](https://huggingface.co/mangsense/codebert_java)

## 5.4 Cooperation
| | |
|---|---|
| Git | <img src="https://github.com/user-attachments/assets/483abc38-ed4d-487c-b43a-3963b33430e6" alt="git" width="100"> |
| [Notion] | <img src="https://github.com/user-attachments/assets/34141eb9-deca-416a-a83f-ff9543cc2f9a" alt="Notion" width="100"> |

<br/>

# 6. Project Structure (프로젝트 구조)
```plaintext
AegisAi
├── .gradle/                  # Gradle 빌드 시스템
├── build/                    # 빌드 산출물
├── gradle/                   # Gradle Wrapper
└── src/                      # 소스 코드 루트
    ├── main/
    │   ├── aegis-ai-frontend/  # React + Vite 프론트엔드
    │   │   ├── dist/           # (프론트엔드 빌드 산출물)
    │   │   ├── node_modules/   # (Node.js 의존성)
    │   │   └── [public/, src/, package.json 등 프론트엔드 소스]
    │   │
    │   ├── java/                 # Spring Boot 백엔드 소스 코드
    │   │   └── org/
    │   │       └── aegisai/
    │   │           ├── config/
    │   │           ├── constant/
    │   │           ├── controller/
    │   │           ├── dto/
    │   │           ├── entity/
    │   │           ├── repository/
    │   │           └── service/
    │   │
    │   └── resources/            # Spring Boot 리소스
    │       └── static/           # 정적 파일 (빌드된 프론트엔드 서빙)
    │
    └── test/                     # 백엔드 테스트 코드
        └── java/
            └── org/
                └── aegisai/
                    └── service/
