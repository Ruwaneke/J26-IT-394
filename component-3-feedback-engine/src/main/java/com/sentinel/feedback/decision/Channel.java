package com.sentinel.feedback.decision;

/** How a notice reaches the developer in the IDE. Interruptive channels count toward the budget. */
public enum Channel {
    INLINE("inline hint", false),
    INLINE_HOVER("inline hint with details on hover", false),
    TOAST_PANEL("notification and side panel", true),
    PANEL_ACK("panel that needs a response", true);

    private final String label;
    private final boolean interruptive;

    Channel(String label, boolean interruptive) {
        this.label = label;
        this.interruptive = interruptive;
    }

    public String label() {
        return label;
    }

    public boolean interruptive() {
        return interruptive;
    }

    public static Channel forLevel(FeedbackLevel level) {
        return switch (level) {
            case L1 -> INLINE;
            case L2 -> INLINE_HOVER;
            case L3 -> TOAST_PANEL;
            case L4 -> PANEL_ACK;
        };
    }
}
