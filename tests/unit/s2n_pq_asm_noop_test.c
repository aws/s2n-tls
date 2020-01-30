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

int main(int argc, char **argv)
{
    /* In CMakeLists.txt, we try_compile the PQ ASM code to determine if the
     * toolchain is compatible with the assembly instructions. Older versions
     * of CMake require that we supply a main() function in the sources that
     * we are passing to try_compile. So, in the try_compile, we use this main()
     * function as a noop. IMPORTANT NOTE: This file is referenced by name
     * in CMakeLists.txt (which is unusual for a unit tst). If this file is
     * renamed, then CMakeLists.txt must be updated as well.*/
    return 0;
}
