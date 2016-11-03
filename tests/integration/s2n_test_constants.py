#
# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

S2N_SSLv3 = 30
S2N_TLS10 = 31
S2N_TLS11 = 32
S2N_TLS12 = 33

# All supported s2n ciphers by (cipher_name, min_proto_vers). 
S2N_CIPHERS= [
    ("AES128-SHA", S2N_TLS10),
    ("DHE-RSA-AES128-SHA", S2N_TLS10),
    ("AES256-SHA", S2N_TLS10),
    ("DHE-RSA-AES256-SHA", S2N_TLS10),
    ("AES128-SHA256", S2N_TLS12),
    ("AES256-SHA256", S2N_TLS12),
    ("DHE-RSA-AES128-SHA256", S2N_TLS12),
    ("DHE-RSA-AES256-SHA256", S2N_TLS12),
    ("AES128-GCM-SHA256", S2N_TLS12),
    ("AES256-GCM-SHA384", S2N_TLS12),
    ("DHE-RSA-AES128-GCM-SHA256", S2N_TLS12),
    ("ECDHE-RSA-AES128-SHA", S2N_TLS10),
    ("ECDHE-RSA-AES256-SHA", S2N_TLS10),
    ("ECDHE-RSA-AES128-SHA256", S2N_TLS12),
    ("ECDHE-RSA-AES256-SHA384", S2N_TLS12),
    ("ECDHE-RSA-AES128-GCM-SHA256", S2N_TLS12),
    ("ECDHE-RSA-AES256-GCM-SHA384", S2N_TLS12),
]

S2N_PROTO_VERS_TO_STR = {
    S2N_SSLv3 : "SSLv3",
    S2N_TLS10 : "TLSv1.0",
    S2N_TLS11 : "TLSv1.1",
    S2N_TLS12 : "TLSv1.2",
}
