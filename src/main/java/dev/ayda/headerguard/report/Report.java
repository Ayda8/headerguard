package dev.ayda.headerguard.report;

import dev.ayda.headerguard.Audit;

/** Turns an audit into text for a human or a machine. */
public interface Report {

    String render(Audit audit);
}
