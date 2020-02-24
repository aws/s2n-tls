# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#######################
# Requires ct-verif to be installed along with all its dependencies
# requires the environment variable CTVERIF_DIR to point to the directory
# where ct-verif is installed
#######################

include ${CTVERIF_DIR}/lib/ct-verif.mk

goals += s2n_constant_time_equals@s2n_safety.c
goals += s2n_constant_time_copy_or_dont@s2n_safety.c

