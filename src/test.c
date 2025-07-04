#include <stdio.h>
#include <stdlib.h>

int main(void) {
	volatile char *target = malloc(1);
	if (!target) {
		perror("malloc");
		return -1;
	}
	*target = 0;

	printf("%p", target);

	(void)getchar();

	*target = 'A';	// WRITE
	asm volatile ("nop");

	char value = *target;	// READ
	asm volatile ("nop");

	*target = *target + 1;	// READ + WRITE
	asm volatile ("nop");

	printf("Read value: %c\n", value);

	*target = 0;
	return 0;
}

