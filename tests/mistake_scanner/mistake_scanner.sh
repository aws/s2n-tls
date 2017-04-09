# Search for `return S2N_ERR_TYPE`. Should be `return S2N_ERROR(S2N_ERR_TYPE);`

grep --exclude-dir="tests" --exclude-dir="docs" -rE "return[ ]+S2N_ERR_TYPE" ../../


# Search for lines that contain memcpy_check followed by an increment or decrement operator. Potentially error-prone because memcpy_check is a macro.

grep --exclude-dir="tests" --exclude-dir="docs" -rE "memcpy_check\(.*(\+\+|\-\-)" ../../


# Search for lines with s2n_stuffer_raw_read that don't have a notnull_check on the next line

grep --exclude-dir="tests" --exclude-dir="docs" -rPzo '(s2n_stuffer_raw_read.*\n)(?!.*notnull_check.*)' ../../


