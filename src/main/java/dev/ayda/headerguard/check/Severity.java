package dev.ayda.headerguard.check;

/** How much a finding costs the score. */
public enum Severity {
    CRITICAL(30),
    HIGH(15),
    MEDIUM(8),
    LOW(3),
    INFO(0);

    private final int penalty;

    Severity(int penalty) {
        this.penalty = penalty;
    }

    public int penalty() {
        return penalty;
    }
}
