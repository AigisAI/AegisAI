// fetch 기반 API 클라이언트

// API 기본 설정
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';
const API_TIMEOUT = 30000; // 30초

// 타임아웃 기능을 추가한 fetch
const fetchWithTimeout = async (url, options = {}, timeout = API_TIMEOUT) => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new Error('요청 시간이 초과되었습니다.');
    }
    throw error;
  }
};

// 공통 에러 처리 함수
const handleApiError = (error, response = null) => {
  console.error('[API Error]', error);
  
  let errorMessage = '서버와 통신 중 오류가 발생했습니다.';
  
  if (response) {
    const status = response.status;
    
    switch (status) {
      case 400:
        errorMessage = '잘못된 요청입니다. 입력값을 확인해주세요.';
        break;
      case 401:
        errorMessage = '인증이 필요합니다.';
        break;
      case 403:
        errorMessage = '접근 권한이 없습니다.';
        break;
      case 404:
        errorMessage = '요청한 리소스를 찾을 수 없습니다.';
        break;
      case 500:
        errorMessage = '서버 내부 오류가 발생했습니다.';
        break;
      case 503:
        errorMessage = '서버를 일시적으로 사용할 수 없습니다.';
        break;
      default:
        errorMessage = `서버 오류 (${status})`;
    }
  } else if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
    errorMessage = '서버와 연결할 수 없습니다. 네트워크를 확인해주세요.';
  } else if (error.message.includes('시간이 초과')) {
    errorMessage = '요청 시간이 초과되었습니다.';
  }
  
  return errorMessage;
};

// 공통 fetch 함수
const apiRequest = async (endpoint, options = {}) => {
  const url = `${API_BASE_URL}${endpoint}`;
  
  console.log(`[API Request] ${options.method || 'GET'} ${endpoint}`);
  
  try {
    const response = await fetchWithTimeout(url, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    });
    
    console.log(`[API Response] ${endpoint} - Status: ${response.status}`);
    
    if (!response.ok) {
      const errorMessage = handleApiError(null, response);
      throw new Error(errorMessage);
    }
    
    const data = await response.json();
    return data;
    
  } catch (error) {
    const errorMessage = handleApiError(error);
    throw new Error(errorMessage);
  }
};

// 코드 취약점 스캔 API
export const scanVulnerability = async (code, language) => {
  try {
    const data = await apiRequest('/api/scan-vulnerability', {
      method: 'POST',
      body: JSON.stringify({ code, language }),
    });
    
    return {
      success: true,
      data: data,
    };
  } catch (error) {
    console.error('취약점 스캔 실패:', error);
    return {
      success: false,
      error: error.message || '취약점 스캔에 실패했습니다.',
    };
  }
};

// 토큰 카운트 API
export const getTokenCount = async (code) => {
  try {
    const data = await apiRequest('/api/token-count', {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
      },
      body: code,
    });
    
    return {
      success: true,
      data: {
        tokens: data.tokens || data.token_count || 0,
        chars: data.chars || data.char_count || code.length,
      },
    };
  } catch (error) {
    console.error('토큰 카운트 실패:', error);
    
    const fallbackTokens = code.split(/\s+/).filter(t => t.length > 0).length;
    const fallbackChars = code.length;
    
    return {
      success: false,
      data: {
        tokens: fallbackTokens,
        chars: fallbackChars,
      },
      error: error.message || '토큰 카운트 API 호출 실패',
    };
  }
};

// 헬스 체크 API
export const healthCheck = async () => {
  try {
    const data = await apiRequest('/api/health', {
      method: 'GET',
    });
    
    return {
      success: true,
      data: data,
    };
  } catch (error) {
    return {
      success: false,
      error: error.message || '서버 상태 확인 실패',
    };
  }
};

export default {
  scanVulnerability,
  getTokenCount,
  healthCheck,
};