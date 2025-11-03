import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Code, Download, TrendingUp, Zap, ChevronDown, Info } from 'lucide-react';

export default function EnhancedSecurityChecker() {
  const [inputCode, setInputCode] = useState('');
  const [language, setLanguage] = useState('Java');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [tokenCount, setTokenCount] = useState(0);
  const [characterCount, setCharacterCount] = useState(0);
  const [vulnerableLines, setVulnerableLines] = useState(new Set());
  const [safeLines, setSafeLines] = useState(new Set());
  const [showCopyNotification, setShowCopyNotification] = useState(false);
  const [notificationMessage, setNotificationMessage] = useState('');
  const lineNumbersRef = React.useRef(null);
  const textareaRef = React.useRef(null);

  // 실시간 토큰 및 문자 카운터
  useEffect(() => {
    const tokens = inputCode.split(/\s+/).filter(t => t.length > 0).length;
    const chars = inputCode.length;
    setTokenCount(tokens);
    setCharacterCount(chars);
    
    // 실시간 취약점 라인 감지
    detectVulnerableLinesRealtime();
  }, [inputCode, language]);

  // 실시간 취약 라인 감지
  const detectVulnerableLinesRealtime = () => {
    const lines = inputCode.split('\n');
    const vulnLines = new Set();
    const okLines = new Set();
    
    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      let isVulnerable = false;
      
      if (language === 'Java') {
        if ((line.includes('Statement') && line.includes('+')) || 
            line.includes('executeQuery') && inputCode.includes('+')) {
          isVulnerable = true;
        }
        if (line.includes('md5') || line.includes('MD5') || line.includes('SHA1')) {
          isVulnerable = true;
        }
        if (line.includes('printStackTrace')) {
          isVulnerable = true;
        }
      } else if (language === 'C' || language === 'C++') {
        if (line.includes('strcpy') || line.includes('gets(')) {
          isVulnerable = true;
        }
        if (line.includes('malloc') && !inputCode.includes('free')) {
          isVulnerable = true;
        }
      }
      
      if (isVulnerable) {
        vulnLines.add(lineNum);
      } else if (line.trim().length > 0) {
        okLines.add(lineNum);
      }
    });
    
    setVulnerableLines(vulnLines);
    setSafeLines(okLines);
  };

  // 취약점 분석
  const analyzeCode = async () => {
    setIsAnalyzing(true);
    
    try {
      // 백엔드 API 호출
      const response = await fetch(`${import.meta.env.VITE_API_URL}/api/scan-vulnerability`, {
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
      
      // 백엔드 응답을 result 형식으로 변환
      setResult({
        isVulnerable: data.vulnerabilities && data.vulnerabilities.length > 0,
        vulnerabilities: data.vulnerabilities || [],
        fixedCode: data.fixed_code || inputCode,
        securityScore: data.security_score || 100,
        scanTime: data.scan_time || '0s',
        statistics: data.statistics || {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        }
      });
      
      setIsAnalyzing(false);
      return;
      
    } catch (error) {
      console.error('백엔드 API 호출 실패:', error);
      alert('백엔드 서버와 연결할 수 없습니다. 데모 모드로 실행합니다.');
      // 에러 발생 시 기존 데모 로직 실행
    }
    
    // 데모 모드 (백엔드 연결 실패 시)
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const vulnerabilities = [];
    
    if (language === 'Java') {
      if (inputCode.includes('Statement') && inputCode.includes('+')) {
        const lineNum = inputCode.split('\n').findIndex(l => (l.includes('Statement') || l.includes('executeQuery')) && inputCode.includes('+')) + 1;
        const badCodeLine = inputCode.split('\n')[lineNum - 1];
        vulnerabilities.push({
          type: 'CWE-89',
          title: 'SQL Injection 취약점',
          severity: 'critical',
          line: lineNum,
          description: 'SQL 쿼리를 문자열 연결(+)로 생성하면 외부 입력값이 직접 쿼리에 삽입되어 공격자가 임의의 SQL 명령을 실행할 수 있습니다. 이는 데이터베이스의 모든 데이터를 조회, 수정, 삭제할 수 있는 심각한 보안 위협입니다.',
          impact: '공격자가 인증 우회, 데이터 유출, 데이터 변조, 시스템 손상을 일으킬 수 있습니다. 실제 사례로 많은 기업이 SQL Injection 공격으로 수백만 건의 개인정보를 유출당했습니다.',
          recommendation: 'PreparedStatement를 사용하여 파라미터화된 쿼리를 작성하세요. 이 방식은 SQL 쿼리와 데이터를 분리하여 입력값이 코드로 해석되지 않도록 합니다.',
          originalCode: badCodeLine.trim(),
          fixedCode: 'PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\npstmt.setString(1, userId);',
          reference: 'OWASP Top 10 - A03:2021 Injection'
        });
      }
      
      if (inputCode.includes('md5') || inputCode.includes('MD5')) {
        const lineNum = inputCode.split('\n').findIndex(l => l.includes('md5') || l.includes('MD5')) + 1;
        const badCodeLine = inputCode.split('\n')[lineNum - 1];
        vulnerabilities.push({
          type: 'CWE-327',
          title: '약한 암호화 알고리즘 사용',
          severity: 'high',
          line: lineNum,
          description: 'MD5는 1996년에 치명적인 결함이 발견된 해시 알고리즘으로, 현대적인 컴퓨팅 환경에서는 몇 초 내에 충돌(collision)을 찾을 수 있습니다. 비밀번호 저장용으로 절대 사용해서는 안 됩니다.',
          impact: '공격자가 레인보우 테이블이나 GPU 기반 크래킹을 통해 해시를 역산할 수 있습니다. 비밀번호 데이터베이스가 유출되면 사용자 계정이 즉시 노출됩니다.',
          recommendation: '비밀번호 저장에는 bcrypt, Argon2, PBKDF2와 같은 전용 알고리즘을 사용하세요. 일반 해시가 필요한 경우 최소 SHA-256 이상을 사용하세요.',
          originalCode: badCodeLine.trim(),
          fixedCode: '// 비밀번호 저장용\nBCryptPasswordEncoder encoder = new BCryptPasswordEncoder();\nString hashedPassword = encoder.encode(password);\n\n// 또는 일반 해시용\nMessageDigest md = MessageDigest.getInstance("SHA-256");',
          reference: 'NIST - Deprecated Hash Algorithms'
        });
      }

      if (inputCode.includes('printStackTrace')) {
        const lineNum = inputCode.split('\n').findIndex(l => l.includes('printStackTrace')) + 1;
        const badCodeLine = inputCode.split('\n')[lineNum - 1];
        vulnerabilities.push({
          type: 'CWE-209',
          title: '민감한 정보 노출',
          severity: 'medium',
          line: lineNum,
          description: 'printStackTrace()는 전체 스택 트레이스를 표준 출력으로 출력하여 시스템 내부 구조, 파일 경로, 클래스 이름 등 공격자에게 유용한 정보를 노출시킵니다. 프로덕션 환경에서는 절대 사용하면 안 됩니다.',
          impact: '공격자가 애플리케이션의 내부 구조를 파악하여 더 정교한 공격을 계획할 수 있습니다. 또한 데이터베이스 연결 정보나 API 키가 노출될 수 있습니다.',
          recommendation: 'Log4j, SLF4J 같은 프로페셔널한 로깅 프레임워크를 사용하고, 로그 레벨을 적절히 설정하세요. 프로덕션에서는 ERROR 레벨만 기록하고 상세 스택 트레이스는 별도 로그 파일에만 저장하세요.',
          originalCode: badCodeLine.trim(),
          fixedCode: 'private static final Logger logger = LoggerFactory.getLogger(ClassName.class);\n\ntry {\n    // code\n} catch (Exception e) {\n    logger.error("작업 실패: {}", e.getMessage());\n    // 상세 로그는 파일에만 기록\n}',
          reference: 'OWASP - Error Handling'
        });
      }
    } else if (language === 'C' || language === 'C++') {
      if (inputCode.includes('strcpy') || inputCode.includes('gets')) {
        const lineNum = inputCode.split('\n').findIndex(l => l.includes('strcpy') || l.includes('gets')) + 1;
        const badCodeLine = inputCode.split('\n')[lineNum - 1];
        vulnerabilities.push({
          type: 'CWE-120',
          title: 'Buffer Overflow 취약점',
          severity: 'critical',
          line: lineNum,
          description: 'strcpy()와 gets()는 대상 버퍼의 크기를 확인하지 않아 버퍼 오버플로우를 일으킬 수 있습니다. 이는 C/C++에서 가장 위험한 취약점 중 하나로, 임의 코드 실행으로 이어질 수 있습니다.',
          impact: '공격자가 메모리를 덮어써서 프로그램의 실행 흐름을 조작하거나, 악성 코드를 주입하여 시스템 전체를 장악할 수 있습니다. 많은 유명한 해킹 사건이 버퍼 오버플로우로 시작되었습니다.',
          recommendation: 'strncpy(), fgets() 같은 크기 제한 함수를 사용하거나, C++의 경우 std::string을 사용하세요. 항상 버퍼 크기를 명시적으로 확인하세요.',
          originalCode: badCodeLine.trim(),
          fixedCode: badCodeLine.includes('strcpy') 
            ? 'strncpy(dest, src, sizeof(dest) - 1);\ndest[sizeof(dest) - 1] = \'\\0\';  // null 종료 보장'
            : 'if (fgets(buffer, sizeof(buffer), stdin) != NULL) {\n    buffer[strcspn(buffer, "\\n")] = 0;  // 개행 제거\n}',
          reference: 'CWE-120 - Buffer Copy without Checking Size of Input'
        });
      }

      if (inputCode.includes('malloc') && !inputCode.includes('free')) {
        const lineNum = inputCode.split('\n').findIndex(l => l.includes('malloc')) + 1;
        const badCodeLine = inputCode.split('\n')[lineNum - 1];
        vulnerabilities.push({
          type: 'CWE-401',
          title: 'Memory Leak (메모리 누수)',
          severity: 'high',
          line: lineNum,
          description: '동적으로 할당한 메모리를 해제하지 않으면 메모리 누수가 발생합니다. 프로그램이 실행되는 동안 메모리 사용량이 계속 증가하여 결국 시스템 자원이 고갈됩니다.',
          impact: '장시간 실행되는 서버 프로그램의 경우 메모리가 점진적으로 소진되어 성능 저하나 프로그램 크래시를 일으킵니다. 최악의 경우 시스템 전체가 불안정해질 수 있습니다.',
          recommendation: 'malloc()으로 할당한 모든 메모리는 반드시 free()로 해제하세요. C++의 경우 스마트 포인터(unique_ptr, shared_ptr)를 사용하면 자동으로 메모리가 관리됩니다.',
          originalCode: badCodeLine.trim(),
          fixedCode: badCodeLine + '\n// ... 사용 후 ...\nfree(ptr);  // 메모리 해제\nptr = NULL;  // 댕글링 포인터 방지',
          reference: 'CWE-401 - Missing Release of Memory after Effective Lifetime'
        });
      }
    }
    
    // 보안 점수 계산
    const maxScore = 100;
    const deduction = vulnerabilities.reduce((sum, v) => {
      if (v.severity === 'critical') return sum + 35;
      if (v.severity === 'high') return sum + 25;
      if (v.severity === 'medium') return sum + 15;
      return sum + 5;
    }, 0);
    const securityScore = Math.max(0, maxScore - deduction);
    
    // 전체 수정 코드 생성
    let fixedCode = inputCode;
    vulnerabilities.forEach(vuln => {
      if (vuln.type === 'CWE-89') {
        fixedCode = fixedCode.replace(
          /Statement.*?\n.*?executeQuery.*/gs,
          'PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\npstmt.setString(1, userId);\nResultSet rs = pstmt.executeQuery();'
        );
      }
      if (vuln.type === 'CWE-327') {
        fixedCode = fixedCode.replace(/MessageDigest\.getInstance\("MD5"\)/g, 'MessageDigest.getInstance("SHA-256")');
        fixedCode = fixedCode.replace(/md5/gi, 'sha256');
      }
      if (vuln.type === 'CWE-209') {
        fixedCode = fixedCode.replace(/e\.printStackTrace\(\);?/g, 'logger.error("오류 발생: {}", e.getMessage());');
      }
      if (vuln.type === 'CWE-120') {
        fixedCode = fixedCode.replace(/strcpy\((.*?),(.*?)\)/g, 'strncpy($1, $2, sizeof($1) - 1)');
        fixedCode = fixedCode.replace(/gets\((.*?)\)/g, 'fgets($1, sizeof($1), stdin)');
      }
      if (vuln.type === 'CWE-401' && fixedCode.includes('malloc')) {
        const lines = fixedCode.split('\n');
        const lastLineWithCode = lines.findLastIndex(l => l.trim() && !l.trim().startsWith('//'));
        lines.splice(lastLineWithCode + 1, 0, '    free(ptr);  // 메모리 해제');
        fixedCode = lines.join('\n');
      }
    });
    
    setResult({
      isVulnerable: vulnerabilities.length > 0,
      vulnerabilities,
      fixedCode,
      securityScore,
      scanTime: '2.3s',
      statistics: {
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length,
      }
    });
    
    setIsAnalyzing(false);
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      default: return 'bg-blue-500';
    }
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(result.fixedCode);
    setNotificationMessage('코드가 복사되었습니다!');
    setShowCopyNotification(true);
    setTimeout(() => setShowCopyNotification(false), 2000);
  };

  const getSeverityBadgeColor = (severity) => {
    switch(severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default: return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  const downloadReport = () => {
    if (!result) return;
    
    const report = `
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      보안 취약점 분석 상세 리포트
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📅 분석 시간: ${new Date().toLocaleString('ko-KR')}
💻 분석 언어: ${language}
🔒 보안 점수: ${result.securityScore}/100
⏱️  분석 소요: ${result.scanTime}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 취약점 통계
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 Critical: ${result.statistics.critical}개
🟠 High:     ${result.statistics.high}개
🟡 Medium:   ${result.statistics.medium}개
🔵 Low:      ${result.statistics.low}개

총 ${result.vulnerabilities.length}개의 취약점이 발견되었습니다.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 상세 취약점 분석
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${result.vulnerabilities.length === 0 ? '\n✅ 발견된 취약점이 없습니다. 코드가 안전합니다!\n' : ''}
${result.vulnerabilities.map((v, i) => `
${'='.repeat(60)}
취약점 #${i + 1}: ${v.title}
${'='.repeat(60)}

📌 분류: ${v.type}
⚠️  심각도: ${v.severity.toUpperCase()}
📍 라인: ${v.line}
📚 참고: ${v.reference || 'N/A'}

📝 설명:
${v.description}

💥 영향:
${v.impact}

✅ 권장 수정:
${v.recommendation}

❌ 취약한 코드:
${v.originalCode}

✓ 수정된 코드:
${v.fixedCode}

`).join('\n')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📄 전체 수정된 코드
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${result.fixedCode}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
생성: Aegis AI - LLM 기반 보안 분석 도구
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    `;
    
    try {
      const blob = new Blob([report], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aegis-ai-security-report-${language}-${Date.now()}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      // Show success notification
      setNotificationMessage('리포트가 다운로드되었습니다!');
      setShowCopyNotification(true);
      setTimeout(() => setShowCopyNotification(false), 2000);
    } catch (error) {
      console.error('리포트 다운로드 실패:', error);
      alert('리포트 다운로드에 실패했습니다. 다시 시도해주세요.');
    }
  };

  const exampleCodes = {
    Java: `import java.sql.*;
import java.security.MessageDigest;

public class VulnerableAuth {
    public void authenticateUser(String username, String password) {
        try {
            Connection conn = getConnection();
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            
            if (rs.next()) {
                System.out.println("Login successful");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}`,
    'C': `#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void processUserInput(char* userInput) {
    char buffer[64];
    char* data;
    
    strcpy(buffer, userInput);
    
    data = malloc(256);
    strcpy(data, userInput);
    
    printf("Processing: %s\\n", buffer);
}`,
    'C++': `#include <iostream>
#include <cstring>

class UserManager {
public:
    void handleInput(char* input) {
        char localBuffer[50];
        strcpy(localBuffer, input);
        
        char* dynamicData = new char[100];
        std::strcpy(dynamicData, input);
        
        std::cout << "Data: " << localBuffer << std::endl;
    }
};`
  };

  const renderCodeWithHighlighting = () => {
    const lines = inputCode.split('\n');
    return lines.map((line, idx) => {
      const lineNum = idx + 1;
      const isVulnerable = vulnerableLines.has(lineNum);
      const isSafe = safeLines.has(lineNum);
      
      return (
        <div key={idx} className="flex" style={{ height: '1.75rem' }}>
          <span className={`inline-block w-14 text-right pr-4 select-none border-r-2 leading-7 font-semibold ${
            isVulnerable 
              ? 'bg-red-600/40 text-red-300 border-red-500' 
              : isSafe
              ? 'bg-green-500/10 text-green-500/60 border-green-500/20'
              : 'text-slate-600 border-slate-800'
          }`}>
            {lineNum}
          </span>
          <span className={`flex-1 px-4 leading-7 ${
            isVulnerable 
              ? 'bg-red-600/25 text-red-100 font-medium' 
              : isSafe
              ? 'text-green-50'
              : 'text-slate-300'
          }`}>
            {line || ' '}
          </span>
        </div>
      );
    });
  };

  return (
    <div className="h-screen bg-slate-950 text-slate-100 flex flex-col overflow-hidden">
      <style>{`
        @keyframes fade-in {
          from {
            opacity: 0;
            transform: translateY(-10px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        .animate-fade-in {
          animation: fade-in 0.3s ease-out;
        }
      `}</style>
      {/* Header */}
      <header className="bg-slate-900 border-b border-slate-800 shadow-xl flex-shrink-0">
        <div className="max-w-full px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-gradient-to-br from-blue-500 to-purple-600 p-2 rounded-lg">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white">Aegis AI</h1>
              <p className="text-xs text-slate-400">실시간 보안 취약점 분석</p>
            </div>
          </div>
          
          {/* Token Counter - Prominent Display */}
          <div className="flex items-center gap-4">
            <div className="bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 flex items-center gap-3">
              <div className="text-right">
                <div className="text-xs text-slate-400">Tokens</div>
                <div className="text-2xl font-bold text-blue-400 font-mono">{tokenCount}</div>
              </div>
              <div className="w-px h-10 bg-slate-700"></div>
              <div className="text-right">
                <div className="text-xs text-slate-400">Characters</div>
                <div className="text-2xl font-bold text-purple-400 font-mono">{characterCount}</div>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content - Single Screen Layout */}
      <main className="flex-1 flex gap-4 p-4 overflow-hidden">
        {/* Left Panel - Code Input (50%) */}
        <div className="w-1/2 flex flex-col bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
          {/* Input Header */}
          <div className="bg-slate-800/50 px-4 py-3 border-b border-slate-700 flex items-center justify-between flex-shrink-0">
            <div className="flex items-center gap-3">
              <Code className="w-4 h-4 text-blue-400" />
              <h2 className="font-semibold text-white text-sm">코드 입력</h2>
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                className="bg-slate-800 text-slate-200 px-2 py-1 rounded border border-slate-700 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="Java">Java</option>
                <option value="C">C</option>
                <option value="C++">C++</option>
              </select>
            </div>
            <button
              onClick={() => setInputCode(exampleCodes[language])}
              className="text-xs text-blue-400 hover:text-blue-300 font-medium"
            >
              예시 코드
            </button>
          </div>
          
          {/* Code Editor */}
          <div className="flex-1 bg-slate-950 flex overflow-hidden">
            {/* Line numbers column */}
            <div 
              ref={lineNumbersRef}
              className="flex-shrink-0 w-14 bg-slate-900 border-r-2 border-slate-800 overflow-hidden" 
              style={{ scrollbarWidth: 'none' }}
            >
              <div>
                {inputCode.split('\n').map((_, idx) => {
                  const lineNum = idx + 1;
                  const isVulnerable = vulnerableLines.has(lineNum);
                  const isSafe = safeLines.has(lineNum);
                  
                  return (
                    <div
                      key={idx}
                      className={`text-right pr-3 select-none font-semibold ${
                        isVulnerable 
                          ? 'bg-red-600/40 text-red-300' 
                          : isSafe
                          ? 'bg-green-500/10 text-green-500/60'
                          : 'text-slate-600'
                      }`}
                      style={{ height: '1.75rem', lineHeight: '1.75rem' }}
                    >
                      {lineNum}
                    </div>
                  );
                })}
                {!inputCode && <div className="text-right pr-3 text-slate-600" style={{ height: '1.75rem', lineHeight: '1.75rem' }}>1</div>}
              </div>
            </div>
            
            {/* Code area - single scroll */}
            <div className="flex-1 relative overflow-y-auto overflow-x-hidden">
              {/* Background highlighting for vulnerable lines */}
              <div className="absolute inset-0 pointer-events-none">
                {inputCode && inputCode.split('\n').map((line, idx) => {
                  const lineNum = idx + 1;
                  const isVulnerable = vulnerableLines.has(lineNum);
                  
                  return (
                    <div
                      key={idx}
                      className={isVulnerable ? 'bg-red-600/25' : ''}
                      style={{ height: '1.75rem' }}
                    />
                  );
                })}
              </div>
              
              {/* Actual textarea */}
              <textarea
                ref={textareaRef}
                value={inputCode}
                onChange={(e) => setInputCode(e.target.value)}
                onScroll={(e) => {
                  if (lineNumbersRef.current && lineNumbersRef.current.firstChild) {
                    lineNumbersRef.current.firstChild.style.transform = `translateY(-${e.target.scrollTop}px)`;
                  }
                }}
                placeholder={`${language} 코드를 입력하면 실시간으로 취약점이 표시됩니다...\n\n🔴 빨간색 = 취약한 라인\n🟢 초록색 = 안전한 라인`}
                className="w-full min-h-full px-4 py-0 bg-transparent text-slate-200 font-mono text-sm resize-none focus:outline-none relative z-10 border-0 outline-none"
                spellCheck="false"
                style={{
                  lineHeight: '1.75rem',
                  caretColor: '#60a5fa',
                  overflow: 'hidden'
                }}
              />
            </div>
          </div>
          
          {/* Analyze Button */}
          <div className="p-4 border-t border-slate-800 flex-shrink-0">
            <button
              onClick={analyzeCode}
              disabled={!inputCode.trim() || isAnalyzing}
              className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 disabled:from-slate-700 disabled:to-slate-700 disabled:cursor-not-allowed text-white font-semibold py-2.5 px-6 rounded-lg transition-all flex items-center justify-center gap-2"
            >
              {isAnalyzing ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>분석 중...</span>
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  <span>취약점 분석 시작</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right Panel - Results (50%) */}
        <div className="w-1/2 flex flex-col gap-4 overflow-hidden">
          {/* Security Score Card */}
          {result && (
            <div className="bg-slate-900 rounded-xl border border-slate-800 p-4 flex-shrink-0">
              <div className="flex items-center gap-6">
                {/* Score Circle */}
                <div className="relative w-24 h-24 flex-shrink-0">
                  <svg className="w-full h-full transform -rotate-90">
                    <circle cx="48" cy="48" r="42" stroke="currentColor" strokeWidth="8" fill="none" className="text-slate-800" />
                    <circle 
                      cx="48" cy="48" r="42" 
                      stroke="currentColor" 
                      strokeWidth="8" 
                      fill="none" 
                      strokeDasharray={`${result.securityScore * 2.64} 999`}
                      className={getScoreColor(result.securityScore)}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className={`text-2xl font-bold ${getScoreColor(result.securityScore)}`}>
                      {result.securityScore}
                    </span>
                  </div>
                </div>
                
                {/* Stats */}
                <div className="flex-1 grid grid-cols-4 gap-2">
                  <div className="text-center">
                    <div className={`text-2xl font-bold text-red-400`}>{result.statistics.critical}</div>
                    <div className="text-xs text-slate-500">Critical</div>
                  </div>
                  <div className="text-center">
                    <div className={`text-2xl font-bold text-orange-400`}>{result.statistics.high}</div>
                    <div className="text-xs text-slate-500">High</div>
                  </div>
                  <div className="text-center">
                    <div className={`text-2xl font-bold text-yellow-400`}>{result.statistics.medium}</div>
                    <div className="text-xs text-slate-500">Medium</div>
                  </div>
                  <div className="text-center">
                    <div className={`text-2xl font-bold text-blue-400`}>{result.statistics.low}</div>
                    <div className="text-xs text-slate-500">Low</div>
                  </div>
                </div>
                
                {/* Download Button */}
                <button
                  onClick={downloadReport}
                  className="flex-shrink-0 bg-slate-800 hover:bg-slate-700 text-white px-4 py-2 rounded-lg flex items-center gap-2 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  <span className="text-sm">리포트</span>
                </button>
              </div>
            </div>
          )}

          {/* Fixed Code Section - Back on Top */}
          {result && result.vulnerabilities.length > 0 && (
            <div className="bg-slate-900 rounded-xl border border-slate-800 flex flex-col h-56 flex-shrink-0">
              <div className="bg-slate-800/50 px-4 py-2 border-b border-slate-700 flex-shrink-0 flex items-center justify-between">
                <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  전체 수정된 코드
                </h3>
                <button
                  onClick={handleCopyCode}
                  className="text-xs bg-slate-700 hover:bg-slate-600 text-slate-200 px-3 py-1 rounded flex items-center gap-1 transition-colors"
                >
                  <Code className="w-3 h-3" />
                  복사
                </button>
              </div>
              <div className="flex-1 overflow-auto p-3">
                <pre className="font-mono text-xs text-green-300 whitespace-pre-wrap break-words">
                  {result.fixedCode}
                </pre>
              </div>
            </div>
          )}

          {/* Vulnerabilities List - Scrollable */}
          <div className="flex-1 bg-slate-900 rounded-xl border border-slate-800 overflow-hidden flex flex-col">
            <div className="bg-slate-800/50 px-4 py-3 border-b border-slate-700 flex items-center justify-between flex-shrink-0">
              <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-orange-400" />
                발견된 취약점
                {result && <span className="text-slate-500">({result.vulnerabilities.length})</span>}
              </h3>
            </div>
            
            <div className="flex-1 overflow-y-auto p-4">
              {!result ? (
                <div className="h-full flex flex-col items-center justify-center text-slate-500">
                  <Shield className="w-12 h-12 mb-3 opacity-20" />
                  <p className="text-sm text-center">코드를 분석하면<br/>취약점 정보가 표시됩니다</p>
                </div>
              ) : result.vulnerabilities.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-green-400">
                  <CheckCircle className="w-12 h-12 mb-3" />
                  <p className="font-semibold">취약점 없음</p>
                  <p className="text-xs text-slate-500 mt-1">안전한 코드입니다 ✨</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {result.vulnerabilities.map((vuln, idx) => (
                    <details key={idx} className="bg-slate-800/50 rounded-lg border border-slate-700 overflow-hidden group">
                      <summary className="p-3 cursor-pointer hover:bg-slate-800 transition-colors flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-mono text-xs text-blue-400">{vuln.type}</span>
                            <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${getSeverityBadgeColor(vuln.severity)}`}>
                              {vuln.severity.toUpperCase()}
                            </span>
                            <span className="text-xs text-slate-500">Line {vuln.line}</span>
                          </div>
                          <h4 className="font-semibold text-white text-sm">{vuln.title}</h4>
                        </div>
                        <ChevronDown className="w-4 h-4 text-slate-400 group-open:rotate-180 transition-transform flex-shrink-0 mt-1" />
                      </summary>
                      
                      <div className="p-4 pt-0 space-y-3 text-sm border-t border-slate-700">
                        {/* Description */}
                        <div>
                          <h5 className="text-xs font-semibold text-slate-400 mb-1 flex items-center gap-1">
                            <Info className="w-3 h-3" />
                            설명
                          </h5>
                          <p className="text-slate-300 leading-relaxed">{vuln.description}</p>
                        </div>
                        
                        {/* Impact */}
                        <div>
                          <h5 className="text-xs font-semibold text-red-400 mb-1">💥 보안 영향</h5>
                          <p className="text-slate-300 leading-relaxed">{vuln.impact}</p>
                        </div>
                        
                        {/* Recommendation */}
                        <div>
                          <h5 className="text-xs font-semibold text-green-400 mb-1">✅ 수정 방법</h5>
                          <p className="text-slate-300 leading-relaxed">{vuln.recommendation}</p>
                        </div>
                        
                        {/* Code Comparison */}
                        <div className="grid grid-cols-2 gap-2">
                          <div>
                            <h5 className="text-xs font-semibold text-red-400 mb-2">❌ 취약한 코드</h5>
                            <div className="bg-red-500/10 border border-red-500/30 rounded p-2 overflow-x-auto">
                              <pre className="text-xs text-red-200 font-mono whitespace-pre-wrap break-all">{vuln.originalCode}</pre>
                            </div>
                          </div>
                          <div>
                            <h5 className="text-xs font-semibold text-green-400 mb-2">✓ 수정된 코드</h5>
                            <div className="bg-green-500/10 border border-green-500/30 rounded p-2 overflow-x-auto">
                              <pre className="text-xs text-green-200 font-mono whitespace-pre-wrap break-all">{vuln.fixedCode}</pre>
                            </div>
                          </div>
                        </div>
                        
                        {/* Reference */}
                        <div className="text-xs text-slate-500 italic">
                          📚 참고: {vuln.reference}
                        </div>
                      </div>
                    </details>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </main>

      {/* Copy/Download Notification Toast */}
      {showCopyNotification && (
        <div className="fixed top-20 right-6 bg-green-600 text-white px-6 py-3 rounded-lg shadow-2xl flex items-center gap-3 animate-fade-in z-50 border border-green-500">
          <CheckCircle className="w-5 h-5" />
          <span className="font-semibold">{notificationMessage}</span>
        </div>
      )}
    </div>
  );
}
