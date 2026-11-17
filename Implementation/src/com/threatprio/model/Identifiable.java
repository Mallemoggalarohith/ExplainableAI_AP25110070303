package com.threatprio.model;

import java.util.Objects;

/** Abstract base class for every domain entity that has a unique identifier. */
public abstract class Identifiable {
    private final String id;

    protected Identifiable(String id) {
        if (id == null || id.isBlank()) throw new IllegalArgumentException("id must not be blank");
        this.id = id;
    }

    public String getId() { return id; }

    /** Short human readable description (abstraction: each subclass defines its own). */
    public abstract String describe();

    @Override public boolean equals(Object o) {
        return o != null && getClass() == o.getClass() && id.equals(((Identifiable) o).id);
    }
    @Override public int hashCode() { return Objects.hash(getClass(), id); }
    @Override public String toString() { return describe(); }
}
