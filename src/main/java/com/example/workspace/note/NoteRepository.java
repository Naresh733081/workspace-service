package com.example.workspace.note;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface NoteRepository extends JpaRepository<Note, Long> {

    // every lookup goes through user_id in the WHERE clause — this is the
    // actual security boundary, written explicitly rather than hidden
    // behind a JPA relationship
    @Query(value = "SELECT * FROM notes WHERE id = :id AND user_id = :userId", nativeQuery = true)
    Optional<Note> findByIdAndUserId(@Param("id") Long id, @Param("userId") Long userId);

    @Query(value = "SELECT * FROM notes WHERE user_id = :userId ORDER BY created_at DESC", nativeQuery = true)
    List<Note> findAllByUserId(@Param("userId") Long userId);
}