# strata-codec

This is a lightweight utility library for encoding binary messages.  It's
oriented towards small messages that comfortably fit in memory and assumes that
we're always reading out of a flat buffer (ie. that we're not reading from a
`Read`).

The format uses an explicitly defined encoding scheme, allowing on-chain messages
to remain compact and their byte layout to stay under our control.

This is essentially a fork of the codec scheme I (Trey Del Bonis) used in
another project of mine, being maintained independently so we can iterate on it
to aid in things like (maybe) making it more zero-copy friendly.
