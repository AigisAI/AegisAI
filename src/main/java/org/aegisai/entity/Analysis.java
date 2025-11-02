package org.aegisai.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.aegisai.constant.AnalysisStatus;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.aegisai.constant.AnalysisStatus.*;

@Entity
@Table(name = "analyses")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Analysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "analysis_id")
    private Integer analysisId;

    /*// User와 N:1 관계
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
*/
    @Enumerated(EnumType.STRING)
    private AnalysisStatus status; // 0: 대기, 2: 완료, 3: 실패

    @CreationTimestamp
    @Column(name = "submitted_at", updatable = false)
    private LocalDateTime submittedAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @Column(name = "high_vul_count")
    private Integer highVulCount;

    @Column(name = "medium_vul_count")
    private Integer mediumVulCount;

    @Column(name = "low_vul_count")
    private Integer lowVulCount;

    // Analysis와 Vulnerability는 1:N 관계
    @OneToMany(mappedBy = "analysis", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Vulnerability> vulnerabilities = new ArrayList<>();

    // 비즈니스 로직: Vulnerability 추가
    public void addVulnerability(Vulnerability vulnerability) {
        vulnerabilities.add(vulnerability);
        vulnerability.setAnalysis(this);
    }

    // 비즈니스 로직: 분석 완료 처리
    public void completeAnalysis(int high, int medium, int low) {
        this.status = COMPLETED;
        this.completedAt = LocalDateTime.now();
        this.highVulCount = high;
        this.mediumVulCount = medium;
        this.lowVulCount = low;
    }

    // 비즈니스 로직: 분석 실패 처리
    public void failAnalysis(String errorMessage) {
        this.status = FAILED;
        this.completedAt = LocalDateTime.now();
        this.errorMessage = errorMessage;
    }
}