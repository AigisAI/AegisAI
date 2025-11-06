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
public interface AnalysisRepository extends JpaRepository<Analysis, Long> {

    // 취약점 정보를 함께 조회 (N+1 문제 방지)
    @Query("SELECT DISTINCT a FROM Analysis a LEFT JOIN FETCH a.vulnerabilities WHERE a.analysisId = :id")
    Optional<Analysis> findByIdWithVulnerabilities(@Param("id") Long id);

    // 최근 분석 결과 조회
    @Query("SELECT a FROM Analysis a ORDER BY a.createdAt DESC")
    List<Analysis> findRecentAnalyses();

    // 특정 기간의 분석 결과 조회
    @Query("SELECT a FROM Analysis a WHERE a.createdAt BETWEEN :startDate AND :endDate ORDER BY a.createdAt DESC")
    List<Analysis> findByDateRange(@Param("startDate") LocalDateTime startDate, 
                                    @Param("endDate") LocalDateTime endDate);

    // 수정 코드가 생성된 분석만 조회
    @Query("SELECT a FROM Analysis a WHERE a.fixedCode IS NOT NULL ORDER BY a.createdAt DESC")
    List<Analysis> findAnalysesWithFixedCode();

    // 취약점이 있는 분석만 조회
    @Query("SELECT DISTINCT a FROM Analysis a JOIN a.vulnerabilities v ORDER BY a.createdAt DESC")
    List<Analysis> findAnalysesWithVulnerabilities();
}
