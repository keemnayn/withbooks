package kr.withbooks.web.service;

import java.util.List;

import kr.withbooks.web.entity.WithMemberView;

public interface WithMemberService {

    List<WithMemberView> getViewById(Long withId);
    
    Integer join(Long userId, Long withId);

    Integer getJoinYn(Long withId, Long userId);

    Integer withdraw(Long withId, Long userId);
}
