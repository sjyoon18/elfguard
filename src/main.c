#include "file_buffer.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("%s\n", argv[1]);

    FileBuffer buffer = {0};

    if (file_buffer_load(argv[1], &buffer) == -1) {
        perror(argv[1]);
        return EXIT_FAILURE;
    }

    printf("Loaded %zu bytes\n", buffer.size);

    file_buffer_destroy(&buffer);
    
    return EXIT_SUCCESS;
}
