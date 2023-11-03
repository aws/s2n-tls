+++
title = 'Entropy'
date = 2023-10-27T13:46:20-07:00
weight = 70
draft = false
+++

> [!NOTE]
> I think this content that describes the should be in the user guide

s2n-tls provides two deterministic random number generators to every thread. **s2n_get_public_random_data()** should be used to generate any data that is exposed in a public context including nonces, initialization vectors, and randomized timing values. **s2n_get_private_random_data()** should be used for data which must be kept secret. Additionally s2n-tls over-rides libcrypto's entropy generation with **s2n_get_private_random_data()**.
