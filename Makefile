CC = clang
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -g -Iinclude

elfguard: src/main.c src/file_buffer.c include/file_buffer.h
	$(CC) $(CFLAGS) src/main.c src/file_buffer.c -o elfguard

.PHONY: clean
clean:
	rm -f elfguard