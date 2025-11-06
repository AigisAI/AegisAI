package org.aegisai.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "analysis")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class Analysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "analysis_id")
    private Long analysisId;

    @Column(name = "inputcode", columnDefinition = "TEXT", nullable = false)
    private String inputCode;

    @Column(name = "fixedcode", columnDefinition = "TEXT")
    private String fixedCode;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "analysis", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Vulnerability> vulnerabilities = new ArrayList<>();

    // 연관관계 편의 메서드
    public void addVulnerability(Vulnerability vulnerability) {
        vulnerabilities.add(vulnerability);
        vulnerability.setAnalysis(this);
    }

    // 비즈니스 로직
    public void updateFixedCode(String fixedCode) {
        this.fixedCode = fixedCode;
    }
}



