/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <string.h>
#include <stdio.h>

#include "tls/s2n_handshake_io.c"

#define MAX_STATE_TYPE (SERVER_CERT_VERIFY + 1)

struct state {
    const char *name;
    int children[MAX_STATE_TYPE];
};

int traverse_handshakes(message_type_t hs_table[S2N_HANDSHAKES_COUNT][S2N_MAX_HANDSHAKE_LENGTH], const char *version, const char *destination)
{
    FILE *out;
    char cmd[255];
    const char *dot = "dot -Tsvg > %s";
    snprintf(cmd, sizeof(cmd), dot, destination);

    out = popen(cmd, "w");
    if (!out) {
        fprintf(stdout, "Failed to run graphviz. Check if you have graphviz installed?\n");
        return 1;
    }

    struct state states[MAX_STATE_TYPE] = { 0 };

    /* generate struct for all states */
    struct state initial = { .name = "INITIAL" };

    for (int i = CLIENT_HELLO; i < MAX_STATE_TYPE; i++) {
        struct state node = { .name = message_names[i] };
        states[i] = node;
    }

    /* traverse handshakes */
    for (int i = 0; i < S2N_HANDSHAKES_COUNT; i++) {
        /* to detect client_hello from empty 0-init value, we check for the following value */
        if (!hs_table[i][1])
            continue;

        for (int j = 0; j < S2N_MAX_HANDSHAKE_LENGTH; j++) {
            message_type_t msg = hs_table[i][j];
            if (j > 0 && !msg)
                continue;

            /* register oneself as parent's child */
            if (j == 0) {
                initial.children[msg] = 1;
            } else {
                states[hs_table[i][j - 1]].children[msg] = 1;
            }
        }
    }

    /* find associated descendents of this node */
    #define print_children(state) \
        for (int c = 0; c < MAX_STATE_TYPE; c++) { \
            if (!state.children[c]) continue; \
            fprintf(out, "    %s -> %s\n", state.name, states[c].name); \
        }

    /* produce dot format header */
    fprintf(out, "digraph G {\n");
    fprintf(out, "    labelloc=\"t\";\n");
    fprintf(out, "    label=<<font point-size='24'>s2n TLS %s State Machine</font>>\n", version);

    /* output initial root node */
    print_children(initial);

    /* iterate thru all possible nodes */
    for (int i = CLIENT_HELLO; i < MAX_STATE_TYPE; i++) {
        print_children(states[i]);
    }

    /* produce dot format footer */
    fprintf(out, "    INITIAL [shape=diamond];\n");
    fprintf(out, "    APPLICATION_DATA [shape=square];\n");
    fprintf(out, "}");

    pclose(out);

    return 0;
}

/*
 * This program generates a visualization of the s2n TLS state machine.
 * It does so by generating a directed acyclic graph, before piping
 * a dot graph format output to graphviz to generate svg files in the
 * document image directory.
 */

int main(int argc, char **argv)
{
    fprintf(stdout, "Generating graphs for s2n TLS state machine...\n");
    traverse_handshakes(handshakes, "1.2", "../../docs/images/tls12_state_machine.svg");
    traverse_handshakes(tls13_handshakes, "1.3", "../../docs/images/tls13_state_machine.svg");
    fprintf(stdout, "Done.\n");
}
