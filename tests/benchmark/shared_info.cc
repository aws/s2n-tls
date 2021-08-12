#include "shared_info.h"

extern "C" {
#include "bin/common.h"

}

struct s2n_cipher_suite **all_suites = cipher_preferences_test_all_tls12.suites;
unsigned int num_suites = cipher_preferences_test_all_tls12.count;


int DEBUG_PRINT = 0;
int WARMUP_ITERS = 1;
unsigned int ITERATIONS = 50;
int use_corked_io = 0;
char bench_format[100] = "--benchmark_out_format=";
char file_prefix[100];
const char *host = "localhost";
const char *port = "8000";
uint8_t insecure = 1;

int benchmark_negotiate(struct s2n_connection *conn, int fd, benchmark::State& state, bool warmup) {
    s2n_blocked_status blocked;
    int s2n_ret;
    if(!warmup) {
        state.ResumeTiming();
    }
    benchmark::DoNotOptimize(s2n_ret = s2n_negotiate(conn, &blocked)); //forces the result to be stored in either memory or a register.
    if(!warmup) {
        state.PauseTiming();
    }
    benchmark::ClobberMemory(); //forces the compiler to perform all pending writes to global memory

    if (s2n_ret != S2N_SUCCESS) {
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Failed to negotiate: '%s'. %s\n",
                    s2n_strerror(s2n_errno, "EN"),
                    s2n_strerror_debug(s2n_errno, "EN"));
            fprintf(stderr, "Alert: %d\n",
                    s2n_connection_get_alert(conn));
            printf("errno: %s\n", strerror(errno));
            S2N_ERROR_PRESERVE_ERRNO();
        }

        if (wait_for_event(fd, blocked) != S2N_SUCCESS) {
            S2N_ERROR_PRESERVE_ERRNO();
        }

        state.SkipWithError("Negotiate Failed\n");
    }

    if(DEBUG_PRINT) {
        print_connection_info(conn);
    }

    return 0;
}


void argument_parse(int argc, char** argv) {
    while (1) {
        int c = getopt(argc, argv, "c:i:w:o:t:sD");
        if (c == -1) {
            break;
        }
        switch (c) {
            case 0:
                /* getopt_long() returns 0 if an option.flag is non-null (Eg "parallelize") */
                break;
            case 'c':
                use_corked_io = atoi(optarg);
                break;
            case 'i':
                ITERATIONS = atoi(optarg);
                break;
            case 'w':
                WARMUP_ITERS = atoi(optarg);
                break;
            case 'o':
                strcpy(file_prefix, optarg);
                break;
            case 't':
                strcat(bench_format, optarg);
                break;
            case 's':
                insecure = 1;
                break;
            case 'D':
                DEBUG_PRINT = 1;
                break;
            case '?':
            default:
                fprintf(stdout, "getopt returned: %d", c);
                break;
        }
    }

    if (optind < argc) {
        host = argv[optind++];
    }

    if (optind < argc) {
        port = argv[optind++];
    }
}