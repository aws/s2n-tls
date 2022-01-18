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

#include <benchmark/benchmark.h>

#include <stdlib.h>
#include <string.h>

#include <vector>

#include "api/s2n.h"

extern "C" {
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_random.h"
}


class TestFixture : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State& state) {
        s2n_result result;
        int rc;

        memset(&r, 0, sizeof(r));
        memset(&entropy, 0, sizeof(entropy));

        pad.resize(state.range(0));
        rc = s2n_blob_init(&r, pad.data(), pad.size());
        assert(rc == 0);

        result  = s2n_get_public_random_data(&r);
        assert(s2n_result_is_ok(result));
        rc = s2n_stuffer_alloc(&entropy, pad.size());
        assert(rc == 0);
        rc = s2n_stuffer_write_bytes(&entropy, pad.data(), pad.size());
        assert(rc == 0);
    }

    void TearDown(const ::benchmark::State& state) {
    }

    std::vector<uint8_t>pad;
    struct s2n_blob r;
    struct s2n_stuffer entropy;

};

BENCHMARK_DEFINE_F(TestFixture, Base64EncodeDecode)(benchmark::State& state) {
    for (auto _ : state) {
        struct s2n_stuffer stuffer = {0};
        struct s2n_stuffer mirror = {0};
        s2n_stuffer_write_base64(&stuffer, &entropy);
        s2n_stuffer_read_base64(&stuffer, &mirror);
    }
}

BENCHMARK_REGISTER_F(TestFixture, Base64EncodeDecode)->DenseRange(1024, 1024 * 1024, 128 * 1024);

int main(int argc, char** argv) {
    ::benchmark::Initialize(&argc, argv);

    int rc = s2n_init();
    assert(rc == 0);

    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
    ::benchmark::RunSpecifiedBenchmarks();

    rc = s2n_cleanup();
    assert(rc == 0);
}


