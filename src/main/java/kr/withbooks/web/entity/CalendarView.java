package kr.withbooks.web.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CalendarView {
  private Long id;
  private Long withId;
  private LocalDateTime startDateTime;
  private LocalDateTime endDateTime;
  private String title; // 일정 제목
  private String location;
}