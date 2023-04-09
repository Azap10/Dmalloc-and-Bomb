#define M61_DISABLE 1
#define HEAVY_HITTER_NUM 10
#define OFFSET_SIZE 256
#define PRESENT 0x55555555
#define NOT_PRESENT 0xAAAAAAAA
#define CANARY_VAL 0x5050505050505050
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>

// You may write code here.
// (Helper functions, types, structs, macros, globals, etc.)

typedef struct heavy_hitters {
    size_t total_bytes[HEAVY_HITTER_NUM];
    size_t num_bytes[HEAVY_HITTER_NUM];
    long lines[HEAVY_HITTER_NUM];
    char* files[HEAVY_HITTER_NUM];
} heavy_hitters;

typedef struct header {
    size_t present;
    size_t bytes;
    const char* file;
    long line;
    struct header* prev;
    struct header* next;
} header;

struct dmalloc_statistics global_stats = {
    .nactive = 0,         // # active allocations
    .active_size = 0,     // # bytes in active allocations
    .ntotal = 0,          // # total allocations
    .total_size = 0,      // # bytes in total allocations
    .nfail = 0,           // # failed allocation attempts
    .fail_size = 0,       // # bytes in failed alloc attempts
    .heap_min = 0xFFFFFFFFFFFFFFFF,  // smallest allocated addr
    .heap_max = 0x0000000000000000   // largest allocated addr
};

header alloc_list_head = {
    .present = 0,
    .bytes = 0,
    .file = "",
    .line = 0,
    .prev = NULL,
    .next = NULL
};

// must be adjusted when HEAVY_HITTER_NUM is adjusted
heavy_hitters global_heavy_hitters = {
    .total_bytes = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    .num_bytes = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    .lines = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
    .files = {}
};

// function to free all memory at end of program
void free_alloc_list() {
    header* cursor1 = alloc_list_head.next;
    if (cursor1 == NULL) {
        return;
    }

    header* cursor2 = cursor1->next;
    while (cursor2 != NULL) {
        free(cursor1);
        cursor1 = cursor2;
        cursor2 = cursor1->next;
    }
    free(cursor1);
    return;
}

/// dmalloc_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then dmalloc_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.

void* dmalloc_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // return null if data plus metadata allocation fails.
    size_t new_sz = sz + sizeof(header) + OFFSET_SIZE + 2 * sizeof(header*);
    // overflow issue
    if (new_sz < sz) {
        global_stats.nfail++;
        global_stats.fail_size += sz;
        return nullptr;
    }
    void* return_pointer = base_malloc(new_sz);
    //printf("%zu, %zu, %p\n", sz, new_sz, return_pointer);
    
    if (return_pointer != NULL) {
        global_stats.nactive++;
        global_stats.ntotal++;
        global_stats.active_size += sz;
        global_stats.total_size += sz;

        // add to linked list
        if (alloc_list_head.next != NULL) {
            alloc_list_head.next->prev = (header*) return_pointer;
        }
        ((header*) return_pointer)->next = alloc_list_head.next;
        ((header*) return_pointer)->prev = NULL;
        ((header*) return_pointer)->file = file;
        ((header*) return_pointer)->line = line;
        alloc_list_head.next = (header*) return_pointer;

        // initialize metadata and return
        ((header*) return_pointer)->bytes = sz;
        ((header*) return_pointer)->present = PRESENT;
        header** return_pointer_cpy = (header**) ((uintptr_t) return_pointer + sizeof(header) + OFFSET_SIZE);
        *return_pointer_cpy = (header*) return_pointer;
        return_pointer_cpy = (header**) ((uintptr_t) return_pointer_cpy + sizeof(header*) + sz);
        *return_pointer_cpy = (header*) return_pointer;

        // set pointer to correct value and update heap_min and heap_max
        return_pointer = (void*) ((uintptr_t) return_pointer + sizeof(header) + OFFSET_SIZE + sizeof(header*));
        if ((uintptr_t) return_pointer < global_stats.heap_min) {
            global_stats.heap_min = (uintptr_t) return_pointer;
        }
        if (((uintptr_t) return_pointer + sz) > global_stats.heap_max) {
            global_stats.heap_max = ((uintptr_t) return_pointer + sz);
        }

        // modify heavy hitters report and return
        size_t min_bytes = sz;
        for (int i = 0; i < HEAVY_HITTER_NUM; i++) {
            if (global_heavy_hitters.num_bytes[i] < min_bytes) {
                min_bytes = global_heavy_hitters.num_bytes[i];
            }
            if (line == global_heavy_hitters.lines[i] && strcmp(file, global_heavy_hitters.files[i]) == 0) {
                global_heavy_hitters.total_bytes[i] += sz;
                global_heavy_hitters.num_bytes[i] += sz;
                return return_pointer;
            }
        }
        for (int i = 0; i < HEAVY_HITTER_NUM; i++) {
            global_heavy_hitters.num_bytes[i] -= min_bytes;
        }
        for (int i = 0; i < HEAVY_HITTER_NUM; i++) {
            if (sz > global_heavy_hitters.num_bytes[i]) {
                global_heavy_hitters.total_bytes[i] = sz;
                global_heavy_hitters.num_bytes[i] = sz;
                global_heavy_hitters.lines[i] = line;
                global_heavy_hitters.files[i] = (char*) file;
                return return_pointer;
            }
        }
        return return_pointer;
    }
    else {
        global_stats.nfail++;
        global_stats.fail_size += sz;
        return NULL;
    }
}


/// dmalloc_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to dmalloc_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

void dmalloc_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // check if NULL or if attempting to access header will result in seg fault
    if (ptr == NULL) {
        return;
    }
    else if (ptr < (void*) global_stats.heap_min || ptr > (void*) global_stats.heap_max) {
        // nullptr
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n",
                file, line, ptr);
        free_alloc_list();
        exit(1);
    }

    ptr = (void*) ((uintptr_t) ptr - sizeof(header) - OFFSET_SIZE - sizeof(header*));
    if (((header*) ptr)->present == PRESENT) {
        void* new_ptr = (void*) ((uintptr_t) ptr + sizeof(header) + OFFSET_SIZE);
        if (*((header**) new_ptr) != (header*) ptr) {
            fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n",
                    file, line, (void*) ((uintptr_t) ptr + sizeof(header) + OFFSET_SIZE + sizeof(header*)));
            free_alloc_list();
            exit(1);
        }
        new_ptr = (void*) ((uintptr_t) ptr + sizeof(header) + OFFSET_SIZE + sizeof(header*) + ((header*) ptr)->bytes);
        if (*((header**) new_ptr) != (header*) ptr) {
            fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n",
                    file, line, (void*) ((uintptr_t) ptr + sizeof(header) + OFFSET_SIZE + sizeof(header*)));
            free_alloc_list();
            exit(1);
        }
        ((header*) ptr)->present = NOT_PRESENT;
        global_stats.nactive--;
        global_stats.active_size -= ((header*) ptr)->bytes;

        // remove ptr from linked list.
        if (((header*) ptr)->prev != NULL) {
            ((header*) ptr)->prev->next = ((header*) ptr)->next;
        }
        else {
            // first node in list
            alloc_list_head.next = ((header*) ptr)->next;
        }
        if (((header*) ptr)->next != NULL) {
            ((header*) ptr)->next->prev = ((header*) ptr)->prev;
        }
        base_free(ptr);
    }
    else if (((header*) ptr)->present == NOT_PRESENT) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n", 
                file, line, (void*) ((uintptr_t) ptr + sizeof(header) + OFFSET_SIZE + sizeof(header*)));
        free_alloc_list();
        exit(1);
    }
    else {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n",
                file, line, (void*) ((uintptr_t) ptr + sizeof(header) + OFFSET_SIZE + sizeof(header*)));
        header* cursor = alloc_list_head.next;
        while (cursor != NULL) {
            if (cursor < ptr && (header*) ((uintptr_t) cursor + cursor->bytes + sizeof(header) + OFFSET_SIZE + sizeof(header*)) > ptr) {
                fprintf(stderr, "  %s:%ld: %p is %zu bytes inside a %zu byte region allocated here\n",
                        cursor->file, cursor->line, (void*) ((uintptr_t) ptr + sizeof(header) + OFFSET_SIZE + sizeof(header*)),
                        (size_t) ((uintptr_t) ptr - (uintptr_t) cursor), cursor->bytes);
                break;
            }
            cursor = cursor->next;
        }
        free_alloc_list();
        exit(1);
        // freed block was not allocated        
    }
    return;
}


/// dmalloc_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // Overflow protection
    if (((nmemb * sz) / sz) != nmemb) {
        global_stats.fail_size += sz * nmemb;
        global_stats.nfail++;
        return nullptr;
    }

    void* ptr = dmalloc_malloc(nmemb * sz, file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}


/// dmalloc_get_statistics(stats)
///    Store the current memory statistics in `*stats`.

void dmalloc_get_statistics(dmalloc_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(dmalloc_statistics));
    stats->nactive = global_stats.nactive;
    stats->active_size = global_stats.active_size;
    stats->ntotal = global_stats.ntotal;
    stats->total_size = global_stats.total_size;
    stats->nfail = global_stats.nfail;
    stats->fail_size = global_stats.fail_size;
    stats->heap_min = global_stats.heap_min;
    stats->heap_max = global_stats.heap_max;
}


/// dmalloc_print_statistics()
///    Print the current memory statistics.

void dmalloc_print_statistics() {
    dmalloc_statistics stats;
    dmalloc_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// dmalloc_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void dmalloc_print_leak_report() {
    header* cursor = alloc_list_head.next;
    while (cursor != NULL) {
        printf("LEAK CHECK: %s:%ld: allocated object %p with size %zu\n", cursor->file, 
                cursor->line, (void*) ((uintptr_t) cursor + sizeof(header) + OFFSET_SIZE + sizeof(header*)), cursor->bytes);
        cursor = cursor->next;
    }
}


/// dmalloc_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

void dmalloc_print_heavy_hitter_report() {
    // selection sort on heavy-hitters
    size_t tmp_bytes;
    char* tmp_file;
    long tmp_line;
    size_t max_bytes;
    size_t max_idx;
    for (int i = 0; i < HEAVY_HITTER_NUM; i++) {
        max_bytes = 0;
        max_idx = 0;
        for (int j = i; j < HEAVY_HITTER_NUM; j++) {
            if (global_heavy_hitters.total_bytes[j] >= max_bytes) {
                max_bytes = global_heavy_hitters.total_bytes[j];
                max_idx = j;
            }
        }
        tmp_bytes = global_heavy_hitters.total_bytes[i];
        tmp_file = global_heavy_hitters.files[i];
        tmp_line = global_heavy_hitters.lines[i];
        global_heavy_hitters.total_bytes[i] = global_heavy_hitters.total_bytes[max_idx];
        global_heavy_hitters.files[i] = global_heavy_hitters.files[max_idx];
        global_heavy_hitters.lines[i] = global_heavy_hitters.lines[max_idx];
        global_heavy_hitters.total_bytes[max_idx] = tmp_bytes;
        global_heavy_hitters.files[max_idx] = tmp_file;
        global_heavy_hitters.lines[max_idx] = tmp_line;
    }
    
    // print out heavy hitters in descending order if they use 1% or more of allocated memory
    double percentage;
    for (int i = 0; i < HEAVY_HITTER_NUM; i++) {
        if ((percentage = 100 * (global_heavy_hitters.total_bytes[i] / (double) global_stats.total_size)) >= 1) {
            printf("HEAVY HITTER: %s:%ld: %zu bytes (~%.2lf%%)\n", global_heavy_hitters.files[i],
                    global_heavy_hitters.lines[i], global_heavy_hitters.total_bytes[i],
                    percentage);
        }
    }
    return;
}
