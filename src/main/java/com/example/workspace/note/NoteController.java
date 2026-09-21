package com.example.workspace.note;

import com.example.workspace.exception.ApiException;
import com.example.workspace.exception.ErrorCode;
import com.example.workspace.user.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notes")
public class NoteController {

    private final NoteRepository noteRepository;

    public NoteController(NoteRepository noteRepository) {
        this.noteRepository = noteRepository;
    }

    // single source of truth for "who is making this request." Every
    // resource controller in this app (Notes) will have
    // an identical private method — that repetition is intentional, it
    // keeps each controller obviously self-contained rather than routing
    // ownership resolution through a shared abstraction too early.
    private Long currentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl principal = (UserDetailsImpl) authentication.getPrincipal();
        return principal.getId();
    }

    @GetMapping
    public List<Note> getNotes() {
        return noteRepository.findAllByUserId(currentUserId());
    }

    @GetMapping("/{id}")
    public Note getNote(@PathVariable Long id) {
        return noteRepository.findByIdAndUserId(id, currentUserId())
                // same 404 whether the id doesn't exist or belongs to
                // someone else — deliberately not leaking which
                .orElseThrow(() -> new ApiException(ErrorCode.RESOURCE_NOT_FOUND, "Note not found: " + id));
    }

    @PostMapping
    public Note createNote(@Valid @RequestBody NoteRequest request) {
        Note note = new Note(request.title(), request.content(), currentUserId());
        return noteRepository.save(note);
    }
}