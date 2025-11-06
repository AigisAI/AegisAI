import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Code, Download, TrendingUp, Zap, ChevronDown, Info } from 'lucide-react';
import { scanVulnerability, getTokenCount } from '../api/api';

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

  // 실시간 토큰 및 문자 카운터 수정
  useEffect(() => {
    const debounceMs = 300;
    let mounted = true;
    const timer = setTimeout(async () => {
      const charsLocal = inputCode.length;
      setCharacterCount(charsLocal);

      if (!inputCode || inputCode.trim().length === 0) {
        setTokenCount(0);
        detectVulnerableLinesRealtime();
        return;
      }

      try {
        // 통합 API 사용
        const result = await getTokenCount(inputCode);
        
        if (!mounted) return;

        if (result.success && result.data) {
          setTokenCount(result.data.tokens);
          setCharacterCount(result.data.chars);
        } else {
          console.warn('토큰 카운트 API 실패, 폴백 사용:', result.error);
          setTokenCount(result.data.tokens);
          setCharacterCount(result.data.chars);
        }
      } catch (err) {
        console.error('토큰 카운트 예외:', err);
        const fallback = inputCode.split(/\s+/).filter(t => t.length > 0).length;
        if (mounted) {
          setTokenCount(fallback);
          setCharacterCount(inputCode.length);
        }
      }

      detectVulnerableLinesRealtime();
    }, debounceMs);

    return () => {
      mounted = false;
      clearTimeout(timer);
    };
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
    if (!inputCode.trim()) {
      alert('분석할 코드를 입력해주세요.');
      return;
    }

    setIsAnalyzing(true);
    
    try {
      // 통합 API 호출
      const result = await scanVulnerability(inputCode, language);
      
      if (result.success && result.data) {
        setResult({
          isVulnerable: result.data.vulnerabilities && result.data.vulnerabilities.length > 0,
          vulnerabilities: result.data.vulnerabilities || [],
          fixedCode: result.data.fixed_code || inputCode,
          securityScore: result.data.security_score || 100,
          scanTime: result.data.scan_time || '0s',
          statistics: result.data.statistics || {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
          }
        });
        
        setIsAnalyzing(false);
        return;
      } else {
        throw new Error(result.error || '알 수 없는 오류');
      }
    } catch (error) {
      console.error('백엔드 API 호출 실패:', error);
      alert(`백엔드 서버와 연결할 수 없습니다.\n오류: ${error.message || error}\n\n데모 모드로 실행합니다.`);
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
          description: 'SQL 쿼리를 문자열 연결(+)로 생성하면 외부 입력값이 직접 쿼리에 삽입되어 공격자가 임의의 SQL 명령을 실행할 수 있습니다.',
          impact: '공격자가 인증 우회, 데이터 유출, 데이터 변조, 시스템 손상을 일으킬 수 있습니다.',
          recommendation: 'PreparedStatement를 사용하여 파라미터화된 쿼리를 작성하세요.',
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
          description: 'MD5는 충돌 공격에 취약한 해시 알고리즘입니다. 비밀번호 저장용으로 사용해서는 안 됩니다.',
          impact: '공격자가 레인보우 테이블이나 GPU 기반 크래킹을 통해 해시를 역산할 수 있습니다.',
          recommendation: '비밀번호 저장에는 bcrypt, Argon2를 사용하세요. 일반 해시는 SHA-256 이상을 사용하세요.',
          originalCode: badCodeLine.trim(),
          fixedCode: 'MessageDigest md = MessageDigest.getInstance("SHA-256");',
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
          description: 'printStackTrace()는 시스템 내부 구조를 노출시켜 공격자에게 유용한 정보를 제공합니다.',
          impact: '공격자가 애플리케이션의 내부 구조를 파악하여 더 정교한 공격을 계획할 수 있습니다.',
          recommendation: 'Log4j, SLF4J 같은 로깅 프레임워크를 사용하고, 로그 레벨을 적절히 설정하세요.',
          originalCode: badCodeLine.trim(),
          fixedCode: 'logger.error("작업 실패: {}", e.getMessage());',
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
          description: 'strcpy()와 gets()는 버퍼 크기를 확인하지 않아 버퍼 오버플로우를 일으킬 수 있습니다.',
          impact: '공격자가 메모리를 덮어써서 프로그램의 실행 흐름을 조작하거나 악성 코드를 주입할 수 있습니다.',
          recommendation: 'strncpy(), fgets() 같은 크기 제한 함수를 사용하거나 std::string을 사용하세요.',
          originalCode: badCodeLine.trim(),
          fixedCode: badCodeLine.includes('strcpy') 
            ? 'strncpy(dest, src, sizeof(dest) - 1);\ndest[sizeof(dest) - 1] = \'\\0\';'
            : 'fgets(buffer, sizeof(buffer), stdin);',
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
          description: '동적으로 할당한 메모리를 해제하지 않으면 메모리 누수가 발생합니다.',
          impact: '장시간 실행되는 프로그램의 경우 메모리가 점진적으로 소진되어 성능 저하나 크래시를 일으킵니다.',
          recommendation: 'malloc()으로 할당한 모든 메모리는 반드시 free()로 해제하세요.',
          originalCode: badCodeLine.trim(),
          fixedCode: badCodeLine + '\n// ... 사용 후 ...\nfree(ptr);\nptr = NULL;',
          reference: 'CWE-401 - Missing Release of Memory after Effective Lifetime'
        });
      }
    }
    
    const totalVulns = vulnerabilities.length;
    const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
    const mediumCount = vulnerabilities.filter(v => v.severity === 'medium').length;
    const lowCount = vulnerabilities.filter(v => v.severity === 'low').length;
    
    let securityScore = 100;
    if (totalVulns > 0) {
      securityScore = Math.max(0, 100 - (criticalCount * 30 + highCount * 20 + mediumCount * 10 + lowCount * 5));
    }
    
    let fixedCode = inputCode;
    vulnerabilities.forEach(vuln => {
      if (vuln.originalCode && vuln.fixedCode) {
        fixedCode = fixedCode.replace(vuln.originalCode, vuln.fixedCode);
      }
    });
    
    setResult({
      isVulnerable: totalVulns > 0,
      vulnerabilities,
      fixedCode,
      securityScore,
      scanTime: '2.1s',
      statistics: {
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount
      }
    });
    
    setIsAnalyzing(false);
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  const getSeverityBadgeColor = (severity) => {
    const colors = {
      critical: 'bg-red-500/20 text-red-300 border-red-500',
      high: 'bg-orange-500/20 text-orange-300 border-orange-500',
      medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500',
      low: 'bg-blue-500/20 text-blue-300 border-blue-500'
    };
    return colors[severity] || colors.low;
  };

  const handleCopyCode = async () => {
    if (result?.fixedCode) {
      try {
        await navigator.clipboard.writeText(result.fixedCode);
        setNotificationMessage('수정된 코드가 클립보드에 복사되었습니다');
        setShowCopyNotification(true);
        setTimeout(() => setShowCopyNotification(false), 3000);
      } catch (err) {
        console.error('복사 실패:', err);
        alert('클립보드 복사에 실패했습니다.');
      }
    }
  };

  const downloadReport = () => {
    if (!result) return;
    
    const reportContent = `
==============================================
🛡️ AEGIS AI 보안 분석 리포트
==============================================

📊 보안 점수: ${result.securityScore}/100
⏱️ 스캔 시간: ${result.scanTime}
🔍 프로그래밍 언어: ${language}

📈 취약점 통계:
  - Critical: ${result.statistics.critical}개
  - High: ${result.statistics.high}개
  - Medium: ${result.statistics.medium}개
  - Low: ${result.statistics.low}개

==============================================
🚨 발견된 취약점
==============================================

${result.vulnerabilities.map((vuln, idx) => `
[${idx + 1}] ${vuln.title}
─────────────────────────────────────────────
📌 유형: ${vuln.type}
⚠️ 심각도: ${vuln.severity.toUpperCase()}
📍 라인: ${vuln.line}

📝 설명:
${vuln.description}

💥 보안 영향:
${vuln.impact}

✅ 수정 방법:
${vuln.recommendation}

❌ 취약한 코드:
${vuln.originalCode}

✓ 수정된 코드:
${vuln.fixedCode}

📚 참고: ${vuln.reference}
`).join('\n')}

==============================================
✨ 전체 수정된 코드
==============================================

${result.fixedCode}

==============================================
생성일시: ${new Date().toLocaleString('ko-KR')}
==============================================
    `.trim();
    
    const blob = new Blob([reportContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis_security_report_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    setNotificationMessage('리포트가 다운로드되었습니다');
    setShowCopyNotification(true);
    setTimeout(() => setShowCopyNotification(false), 3000);
  };

  const handleScroll = () => {
    if (textareaRef.current && lineNumbersRef.current) {
      lineNumbersRef.current.scrollTop = textareaRef.current.scrollTop;
    }
  };

  const renderLineNumbers = () => {
    const lines = inputCode.split('\n');
    return lines.map((_, idx) => {
      const lineNum = idx + 1;
      const isVulnerable = vulnerableLines.has(lineNum);
      const isSafe = safeLines.has(lineNum);
      
      return (
        <div
          key={lineNum}
          className={`h-6 px-2 text-right text-xs select-none transition-colors ${
            isVulnerable
              ? 'bg-red-500/20 text-red-400 font-bold'
              : isSafe
              ? 'text-slate-600'
              : 'text-slate-700'
          }`}
        >
          {lineNum}
        </div>
      );
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      {/* Header */}
      <header className="bg-slate-900/80 backdrop-blur border-b border-slate-800 sticky top-0 z-40">
        <div className="max-w-[1800px] mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="bg-gradient-to-br from-blue-500 to-purple-600 p-2 rounded-lg">
                <Shield className="w-6 h-6" />
              </div>
              <div>
                <h1 className="text-xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                  AEGIS AI
                </h1>
                <p className="text-xs text-slate-400">AI-Powered Code Security Scanner</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-sm">
                <div className="flex items-center gap-1 px-3 py-1 bg-slate-800 rounded-lg">
                  <Zap className="w-4 h-4 text-yellow-400" />
                  <span className="text-slate-400">토큰:</span>
                  <span className="font-mono text-white">{tokenCount.toLocaleString()}</span>
                </div>
                <div className="flex items-center gap-1 px-3 py-1 bg-slate-800 rounded-lg">
                  <Code className="w-4 h-4 text-blue-400" />
                  <span className="text-slate-400">문자:</span>
                  <span className="font-mono text-white">{characterCount.toLocaleString()}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-[1800px] mx-auto p-6 flex gap-6 h-[calc(100vh-88px)]">
        {/* Left Panel - Code Input (50%) */}
        <div className="w-1/2 flex flex-col gap-4">
          {/* Language Selector */}
          <div className="flex items-center gap-3 bg-slate-900 rounded-xl border border-slate-800 p-3">
            <span className="text-sm text-slate-400 font-semibold">언어:</span>
            <div className="flex gap-2">
              {['Java', 'C', 'C++'].map((lang) => (
                <button
                  key={lang}
                  onClick={() => setLanguage(lang)}
                  className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-all ${
                    language === lang
                      ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/30'
                      : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                  }`}
                >
                  {lang}
                </button>
              ))}
            </div>
          </div>

          {/* Code Editor */}
          <div className="flex-1 bg-slate-900 rounded-xl border border-slate-800 overflow-hidden flex flex-col">
            <div className="bg-slate-800/50 px-4 py-2 border-b border-slate-700 flex items-center justify-between">
              <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                <Code className="w-4 h-4 text-blue-400" />
                코드 입력
              </h3>
            </div>
            
            <div className="flex-1 flex overflow-hidden">
              {/* Line Numbers */}
              <div
                ref={lineNumbersRef}
                className="overflow-hidden bg-slate-800/30 border-r border-slate-700"
                style={{ overflowY: 'hidden' }}
              >
                {renderLineNumbers()}
              </div>
              
              {/* Code Textarea */}
              <textarea
                ref={textareaRef}
                value={inputCode}
                onChange={(e) => setInputCode(e.target.value)}
                onScroll={handleScroll}
                placeholder={`${language} 코드를 입력하세요...\n\n예시 (SQL Injection):\nString query = "SELECT * FROM users WHERE id=" + userId;\nStatement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery(query);`}
                className="flex-1 bg-transparent text-white font-mono text-sm p-4 resize-none focus:outline-none placeholder:text-slate-600 leading-6"
                spellCheck="false"
              />
            </div>
          </div>

          {/* Analyze Button */}
          <div className="flex gap-3">
            <button
              onClick={analyzeCode}
              disabled={isAnalyzing || !inputCode.trim()}
              className={`flex-1 py-3 rounded-xl font-semibold text-sm flex items-center justify-center gap-2 transition-all ${
                isAnalyzing || !inputCode.trim()
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white shadow-lg shadow-blue-500/30'
              }`}
            >
              {isAnalyzing ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent"></div>
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

          {/* Fixed Code Section */}
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