package com.example.app.domain;

import java.time.Instant;

public class LogEntry {
    private final Instant time;
    private final String level;
    private final String event;
    private final String details;

    public LogEntry(Instant time, String level, String event, String details) {
        this.time = time;
        this.level = level;
        this.event = event;
        this.details = details;
    }

    public Instant getTime() { return time; }
    public String getLevel() { return level; }
    public String getEvent() { return event; }
    public String getDetails() { return details; }
}
