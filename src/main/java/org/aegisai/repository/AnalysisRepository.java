package org.aegisai.repository;

import org.aegisai.entity.Analysis;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface AnalysisRepository extends JpaRepository<Analysis, Integer> {

    // 특정 사용자의 모든 분석 조회
    List<Analysis> findByUser_UserId(Integer userId);

    // 특정 사용자의 분석을 최신순으로 조회
    List<Analysis> findByUser_UserIdOrderBySubmittedAtDesc(Integer userId);

    // 상태별 분석 조회 (0: 대기, 2: 완료, 3: 실패)
    List<Analysis> findByStatus(Integer status);

    // 특정 사용자의 특정 상태 분석 조회
    List<Analysis> findByUser_UserIdAndStatus(Integer userId, Integer status);

    // 완료된 분석만 조회
    @Query("SELECT a FROM Analysis a WHERE a.status = 2")
    List<Analysis> findCompletedAnalyses();

    // 대기 중인 분석만 조회
    @Query("SELECT a FROM Analysis a WHERE a.status = 0")
    List<Analysis> findPendingAnalyses();

    // 실패한 분석만 조회
    @Query("SELECT a FROM Analysis a WHERE a.status = 3")
    List<Analysis> findFailedAnalyses();

    // 특정 기간 내 분석 조회
    List<Analysis> findBySubmittedAtBetween(LocalDateTime start, LocalDateTime end);

    // 특정 사용자의 최근 N개 분석 조회
    List<Analysis> findTop10ByUser_UserIdOrderBySubmittedAtDesc(Integer userId);

    // 분석 ID로 상세 조회 (Vulnerability도 함께 가져오기)
    @Query("SELECT a FROM Analysis a LEFT JOIN FETCH a.vulnerabilities WHERE a.analysisId = :analysisId")
    Optional<Analysis> findByIdWithVulnerabilities(@Param("analysisId") Integer analysisId);

    // 전체 분석 개수 (사용자별)
    long countByUser_UserId(Integer userId);

    // 완료된 분석 개수 (사용자별)
    long countByUser_UserIdAndStatus(Integer userId, Integer status);
}