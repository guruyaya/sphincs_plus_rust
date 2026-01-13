# rust sphincs plus

A rust implementation of the ideas and thecnics used in sphincs plus.

This project uses a few twists on the original formula for sphincs plus:

1. This implementation allows, if configured, stateful manegment of the keys used. It uses a DB that keeps track of the last key in the sequance used, and the timstamp of creation. The key number used, will either be the minimum of the minute from the time of creation * 60, or the next number in the sequance. This ensures a lost DB will still only produce keys never used before. However it limits the creation of new keys to 120 years. Somehow - I think we'll survive.

2. This implementation, allows both 2^64 keys creation, and 2^32 keys creation, reducing the signature size by half, and the runtime for signing. This design choise is related to the stateful manegment, as 2^32 is too small of a key to use, in a stateless signature scheme.

3. We are using SHA256 not only as a hash function, but also as a random generator. While there is no known attack on CSPRNG at the moment, the future may proove us wrong. However, if an attack will be found against SHA256 - SPHINCS+ is lost, if we use SHA256 as generator or not.
