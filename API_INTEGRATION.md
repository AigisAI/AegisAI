# 🔌 백엔드 API 연동 가이드

## 📋 백엔드 API 스펙

### 엔드포인트
```
POST http://localhost:8080/scan-vulnerability
```

### 요청 형식
```json
{
  "code": "취약한 코드 문자열",
  "language": "Java"  // 또는 "C", "C++"
}
```

### 응답 형식
```json
{
  "security_score": 35,
  "scan_time": "2.1s",
  "vulnerabilities": [
    {
      "type": "CWE-89",
      "title": "SQL Injection 취약점",
      "severity": "critical",
      "line": 6,
      "description": "설명...",
      "impact": "영향...",
      "recommendation": "권장사항...",
      "originalCode": "원본 코드 라인",
      "fixedCode": "수정된 코드",
      "reference": "OWASP Top 10"
    }
  ],
  "fixed_code": "전체 수정된 코드",
  "statistics": {
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

## ⚙️ 환경 설정

### 1. `.env` 파일 생성

프로젝트 루트에 `.env` 파일을 만들고:

```env
# 개발 환경
VITE_API_URL=http://localhost:8080

# 프로덕션 환경에서는:
# VITE_API_URL=https://api.aegis-ai.com
```

### 2. 환경 변수 사용

코드에서 이렇게 사용:
```javascript
const apiUrl = import.meta.env.VITE_API_URL;
```

⚠️ **주의**: Vite에서는 `process.env`가 아니라 `import.meta.env`를 사용합니다!

## 🚀 API 호출 코드

`src/components/SecurityChecker.jsx`의 `analyzeCode` 함수:

```javascript
const analyzeCode = async () => {
  setIsAnalyzing(true);
  
  try {
    const response = await fetch(`${import.meta.env.VITE_API_URL}/scan-vulnerability`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code: inputCode,
        language: language
      })
    });

    if (!response.ok) {
      throw new Error(`API 오류: ${response.status}`);
    }

    const data = await response.json();
    
    // 결과 처리
    setResult({
      isVulnerable: data.vulnerabilities.length > 0,
      vulnerabilities: data.vulnerabilities,
      fixedCode: data.fixed_code,
      securityScore: data.security_score,
      scanTime: data.scan_time,
      statistics: data.statistics
    });
    
  } catch (error) {
    console.error('백엔드 연결 실패:', error);
    alert('백엔드 서버에 연결할 수 없습니다.');
  } finally {
    setIsAnalyzing(false);
  }
};
```

## 🧪 테스트 방법

### 1. 백엔드 서버 실행

```bash
# 백엔드 디렉토리에서
python app.py  # 또는 백엔드 실행 명령어
```

서버가 `http://localhost:8080`에서 실행되는지 확인

### 2. 프론트엔드 실행

```bash
# 프론트엔드 디렉토리에서
npm run dev
```

### 3. 테스트

1. `http://localhost:5173` 접속
2. 예시 코드 입력
3. "취약점 분석" 버튼 클릭
4. 브라우저 개발자 도구(F12) → Network 탭에서 API 호출 확인

## 🔧 CORS 문제 해결

만약 CORS 오류가 발생하면 백엔드에서 설정 필요:

### Python Flask 예시
```python
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # 모든 도메인 허용

# 또는 특정 도메인만:
# CORS(app, origins=["http://localhost:5173"])
```

### Python FastAPI 예시
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## 🌐 프로덕션 배포 시

### 환경 변수 설정

배포 플랫폼(Vercel, Netlify 등)에서:

```
VITE_API_URL=https://api.aegis-ai.com
```

### 백엔드 URL 변경

`.env` 파일을 수정하거나 배포 시 환경 변수 설정

## 🐛 디버깅

### 백엔드 연결 확인

```javascript
// 임시 테스트 코드
fetch(`${import.meta.env.VITE_API_URL}/scan-vulnerability`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ code: 'test', language: 'Java' })
})
.then(res => res.json())
.then(data => console.log('Success:', data))
.catch(err => console.error('Error:', err));
```

### 브라우저 콘솔 확인

F12 → Console 탭에서 에러 메시지 확인

## ✅ 체크리스트

- [ ] `.env` 파일 생성
- [ ] `VITE_API_URL` 설정
- [ ] 백엔드 서버 실행 중
- [ ] 프론트엔드 재시작 (`npm run dev`)
- [ ] CORS 설정 완료
- [ ] API 응답 형식 일치 확인

## 📞 문제 발생 시

1. 백엔드 로그 확인
2. 프론트엔드 Network 탭 확인
3. CORS 헤더 확인
4. 요청/응답 JSON 형식 확인
