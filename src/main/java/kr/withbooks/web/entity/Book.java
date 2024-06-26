package kr.withbooks.web.entity;

import java.time.LocalDateTime;
import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Book {
    private Long id;
    private String title;
    private String purchaseLink;
    private Long cid;
    private String author;
    private Date pubDate;
    private String description;
    private String isbn13;
    private Integer price;
    private String cover;
    private Integer publicYn;
    private long categoryId;
    private LocalDateTime regDate;
    private String publisher;
    private String categoryName;
}
