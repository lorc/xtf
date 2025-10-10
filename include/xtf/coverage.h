#ifndef XTL_COVERAGE_H
#define XTL_COVERAGE_H

int64_t coverage_get_size(void);
int coverage_read_data(void *buffer, uint32_t size);
int coverage_dump(void);
void *coverage_get(int64_t *size);


#endif /* XTL_COVERAGE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
