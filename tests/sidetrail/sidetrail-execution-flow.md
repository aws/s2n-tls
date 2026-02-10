# Sidetrail Execution Flow

This diagram shows the execution flow for all sidetrail verification jobs. Each test follows the same pattern with test-specific source files and patches.

```mermaid
graph TD
    A[run.sh] --> B[copy_as_needed.sh]
    B --> C1[Copy s2n_hmac.c/h]
    B --> C2[Apply hmac.patch]
    B --> C3[Copy stub s2n_hash.c/h]
    B --> C4[Copy s2n_errno.c]
    B --> C5[Copy s2n_cbc.c]
    B --> C6[Apply cbc.patch]
    B --> C7[Copy s2n_safety.c]
    B --> C8[Apply safety.patch]
    B --> C9[Copy stub files]
    
    C1 --> D[make clean]
    C2 --> D
    C3 --> D
    C4 --> D
    C5 --> D
    C6 --> D
    C7 --> D
    C8 --> D
    C9 --> D
    
    D --> E[make - ct-verif.mk]
    
    E --> F1[Compile Phase]
    F1 --> F2[ct-verif.rb --no-product --no-verify]
    F2 --> F3[Generate .compiled.bpl]
    
    F3 --> G1[Product Phase]
    G1 --> G2[ct-verif.rb --no-compile --no-verify]
    G2 --> G3[Generate .product.bpl]
    
    G3 --> H1[Verify Phase]
    H1 --> H2[ct-verif.rb --no-compile --no-product]
    H2 --> H3[Run Boogie verifier]
    H3 --> H4[Check timing leakage ≤ 68 cycles]
    
    H4 --> I[Output: .log file]
    
    style A fill:#e1f5ff
    style E fill:#ffe1e1
    style F1 fill:#fff4e1
    style G1 fill:#fff4e1
    style H1 fill:#fff4e1
    style I fill:#e1ffe1
```

## Phases

1. **Setup** (`copy_as_needed.sh`): Copies source files and applies patches to add timing invariants
2. **Compile**: Converts C to Boogie intermediate language (.compiled.bpl)
3. **Product**: Creates self-composition product for timing analysis (.product.bpl)
4. **Verify**: Runs Boogie to verify timing leakage constraints

## Sidetrail Tests

All tests follow this same execution pattern:

- **s2n-cbc**: Verifies CBC cipher timing (leakage ≤ 68 cycles)
- **s2n-record-read-aead**: Verifies AEAD record reading timing
- **s2n-record-read-cbc**: Verifies CBC record reading timing
- **s2n-record-read-composite**: Verifies composite cipher record reading timing
- **s2n-record-read-stream**: Verifies stream cipher record reading timing
- **s2n-record-read-cbc-negative-test**: Negative test (expects verification failure)

## Performance Notes

Any slowdowns typically occurs in the **Verify phase** (Boogie solver) where heavy SMT solving happens. The `smtlog += p.smt2` in Makefiles logs SMT queries for debugging.

## Configuration Options

Each test's `Makefile` can set:
- `unroll`: Loop unroll limit (controls state space size)
- `looplim`: Loop analysis limit
- `time`: Timeout in seconds
- `timing`: Enable timing analysis
- `smtlog`: SMT query log file
