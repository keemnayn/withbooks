package kr.withbooks.web.repository;

import kr.withbooks.web.entity.DebateBoard;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface DebateBoardRepository {

    void save(DebateBoard debateBoard);

    DebateBoard findById(Long id);

    void update(DebateBoard debateBoard);

    void delete(Long id);
}
