# strata-codec

This is a lightweight utility library for encoding binary messages.  It's
oriented towards small messages that comfortably fit in memory and assumes that
we're always reading out of a flat buffer (ie. that we're not reading from a
`Read`).

We currently use `borsh` to accomplish these tasks, but it's not well-suited for
the task and we are incrementally trying to migrate to either SSZ for general
types or, in this case, a more explicitly-defined encoding scheme.

This is essentially a fork of the codec scheme I (Trey Del Bonis) used in
another project of mine, being maintained independently so we can iterate on it
to aid in things like (maybe) making it more zero-copy friendly.
