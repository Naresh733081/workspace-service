package com.example.workspace.note;

import jakarta.validation.constraints.NotBlank;

public record NoteRequest(
        @NotBlank(message = "Title must not be blank")
        String title,

        String content
) {
}