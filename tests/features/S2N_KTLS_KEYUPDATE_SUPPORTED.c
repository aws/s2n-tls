/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/* Gate kTLS support only to Linux. Add other platforms once they have been tested. */
#if defined(__linux__)
    #include <linux/snmp.h>
#endif

int main()
{
    int counters[] = { LINUX_MIB_TLSRXREKEYOK, LINUX_MIB_TLSRXREKEYERROR, LINUX_MIB_TLSTXREKEYOK, LINUX_MIB_TLSTXREKEYERROR, LINUX_MIB_TLSRXREKEYRECEIVED };
  
    return 0;
}
