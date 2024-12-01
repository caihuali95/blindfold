#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

const unsigned long BLINDFOLD_SYSCALL = 453;
const unsigned long ROUNDS = 10000;

static inline void print_usage(char* name) {
	fprintf(stderr, "nano benchmark usage: %s -n\n", name);
	exit(1);
}

int main(int argc, char* argv[]) {
	unsigned long round, i, j, cmd, a1, a2, a3, a4, a5;
	unsigned long cost[4][4], cnt[4][4], t0, t1, t2, t3, t4, t5, t6;

	if (argc <= 1) print_usage(argv[0]);
	if (strcmp(argv[1], "-n") == 0) {				// nano benchmark: ./nano -n
		for (i = 0; i < 4; i++)
			for (j = 0; j < 4; j++) {
				cost[i][j] = 0;
				cnt[i][j] = 0;
			}
		syscall(BLINDFOLD_SYSCALL, 0xdb0, 0, 0, 0, NULL);
		for (round = 0; round < ROUNDS; ++round) {	// EL0 -> EL1 -> EL2 -> EL1 -> EL0
			asm volatile ("mov x9, #0\n"
						  "mov x8, %5\n"
						  "mov x0, %6\n"			// let x0 = 0 due to limited space in exception table entry
						  "mrs x1, pmccntr_el0\n"
						  "svc #0\n"
						  "mrs x0, pmccntr_el0\n"
						  "mov %0, x1\n"
						  "mov %1, x2\n"
						  "mov %2, x3\n"
						  "mov %3, x4\n"
						  "mov %4, x0\n"
						: "=r" (t0), "=r" (t1), "=r" (t2), "=r" (t3), "=r" (t4)
						: "r" (BLINDFOLD_SYSCALL), "r" (0x0)
						: "x0", "x1", "x2", "x3", "x4", "x8", "x9");
			cost[0][1] += t1 - t0;	// after svc - before svc
			cost[1][2] += t2 - t1;	// after hvc - before hvc
			cost[2][1] += t3 - t2;	// after eret 1 - before eret 1
			cost[1][0] += t4 - t3;	// after eret 2 - before eret 2
			cnt[0][1] += 1;
			cnt[1][2] += 1;
			cnt[2][1] += 1;
			cnt[1][0] += 1;
			//if (round < 3) printf("for debug: %ld\t%ld\t%ld\t%ld\t%ld\n", t0, t1, t2, t3, t4);
		}
		for (round = 0; round < ROUNDS; ++round) {	// EL0 -> EL2 -> EL3 -> EL2 -> EL0
			asm volatile ("mov x9, %7\n"
						  "mov x8, #0\n"
						  "mrs x1, pmccntr_el0\n"
						  "mrs x9, ctr_el0\n"
						  "mrs x0, pmccntr_el0\n"
						  "mov %0, x1\n"
						  "mov %1, x2\n"
						  "mov %2, x3\n"
						  "mov %3, x4\n"
						  "mov %4, x5\n"
						  "mov %5, x6\n"
						  "mov %6, x0\n"
						: "=r" (t0), "=r" (t1), "=r" (t2), "=r" (t3), "=r" (t4), "=r" (t5), "=r" (t6)
						: "r" (0xdbe)
						: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x8", "x9");
			cost[0][2] += t1 - t0;	// after ctr - before ctr
			cost[2][3] += t2 - t1;	// after smc - before smc
			cost[3][2] += t4 - t3;	// after eret 1 - before eret 1
			cost[2][0] += t6 - t5;	// after eret 2 - before eret 2
			cnt[0][2] += 1;
			cnt[2][3] += 1;
			cnt[3][2] += 1;
			cnt[2][0] += 1;
			//if (round < 3) printf("for debug: %ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\n", t0, t1, t2, t3, t4, t5, t6);
		}
		for (round = 0; round < ROUNDS; ++round) {	// EL0 -> EL2 -> EL3 -> EL0
			asm volatile ("mov x9, %5\n"
						  "mov x8, #0\n"
						  "mrs x1, pmccntr_el0\n"
						  "mrs x9, ctr_el0\n"
						  "mrs x0, pmccntr_el0\n"
						  "mov %0, x1\n"
						  "mov %1, x2\n"
						  "mov %2, x3\n"
						  "mov %3, x4\n"
						  "mov %4, x0\n"
						: "=r" (t0), "=r" (t1), "=r" (t2), "=r" (t3), "=r" (t4)
						: "r" (0xdbd)
						: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x8", "x9");
			cost[0][2] += t1 - t0;	// after ctr - before ctr
			cost[2][3] += t2 - t1;	// after smc - before smc
			cost[3][0] += t4 - t3;	// before eret - after eret
			cnt[0][2] += 1;
			cnt[2][3] += 1;
			cnt[3][0] += 1;
			//if (round < 3) printf("for debug: %ld\t%ld\t%ld\t%ld\t%ld\n", t0, t1, t2, t3, t4);
		}
		printf("nano results:\n");
		for (i = 0; i < 4; i++) {
			for (j = 0; j < 4; j++)
				printf("%ld\t", cost[i][j] / cnt[i][j]);
			printf("\n");
		}
		sleep(1);
		syscall(BLINDFOLD_SYSCALL, 0xdbc, 0, 0, 0, NULL);	// trigger kernel to measure EL1 -> EL3 -> EL1
	} else {												// trigger kernel: ./nano cmd a1 a2 a3 a4 a5
		cmd = (argc > 1)? strtol(argv[1], NULL, 0) : 0;
		a1  = (argc > 2)? strtol(argv[2], NULL, 0) : 0;
		a2  = (argc > 3)? strtol(argv[3], NULL, 0) : 0;
		a3  = (argc > 4)? strtol(argv[4], NULL, 0) : 0;
		a4  = (argc > 5)? strtol(argv[5], NULL, 0) : 0;
		a5  = (argc > 6)? strtol(argv[6], NULL, 0) : 0;
		syscall(BLINDFOLD_SYSCALL, cmd, a1, a2, a3, a4, a5);
	}
	return 0;
}
