#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <signal.h>
#include <wait.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <errno.h>

#define PAGE_SIZE    4096

// The futex word used for synchronization
int futex_var = 0;

// Wrapper function for the futex system call
int futex(int *uaddr, int futex_op, int val, const struct timespec *timeout, int *uaddr2, int val3) {
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr, val3);
}

// Function for the thread that waits on the futex
void *waiter(void *arg) {
    printf("Waiter thread: Waiting on the futex...\n");
    int s = futex(&futex_var, FUTEX_WAIT, 0, NULL, NULL, 0);
    if (s == -1 && errno != EAGAIN)
        perror("FUTEX_WAIT");
    else
        printf("Waiter thread: Woke up!\n");
    return 0;
}

// Function for the thread that wakes the waiter
void *waker(void *arg) {
    printf("Waker thread: Sleeping for a bit...\n");
    sleep(1);       // Sleep for a second to ensure the waiter is waiting
    futex_var = 1;  // Update the futex word
    printf("Waker thread: Waking the waiter...\n");
    int s = futex(&futex_var, FUTEX_WAKE, 1, NULL, NULL, 0);
    if (s == -1)
        perror("FUTEX_WAKE");
    return 0;
}

void *print_message_function( void *arg )
{
    int N, i, err, *ptr;
    char *message = (char *) arg;
    printf("%s \n", message);

    N = 5;                                              // test mmap
    ptr = (int*) mmap ( NULL, N * sizeof(int), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0 );
    
    if (ptr == MAP_FAILED) {
        printf("Mapping Failed\n");
        return NULL;
    }

    for (i = 0; i < N; i++)
        ptr[i] = i * 10;

    for (i = 0; i < N; i++)
        printf("[%d] ", ptr[i]);
    printf("\n");

    err = munmap(ptr, 5 * sizeof(int));                 // test munmap
    if (err != 0) {
        printf("UnMapping Failed\n");
        return NULL;
    }
}

int val = 10;
void handler(int sig)
{
    val += 5;
}

int main() {
    pthread_t thread1, thread2, thread3;
    char *message1 = "Thread 1";
    char *message2 = "Thread 2";
    char *message3 = "Thread 3";
    int  iret1, iret2, iret3, pid, i;

    signal(SIGCHLD, handler);
    signal(SIGUSR1, handler);

    pid = fork();                                       // test fork
    if (pid < 0) printf("fork: error\n");
    if (pid == 0) {
        val -= 3;
        printf("child, val = 0x%x\n", val);
        print_message_function((void*) message1);
        print_message_function((void*) message2);
        print_message_function((void*) message3);
        exit(0);
    } else {
        kill(pid, SIGUSR1);                             // test signal
        waitpid(pid, NULL, 0);
        printf("father, val = 0x%x\n", val);
    }

    signal(SIGUSR1, handler);
                                                        // test clone
    iret1 = pthread_create(&thread1, NULL, print_message_function, (void*) message1);
    iret2 = pthread_create(&thread2, NULL, print_message_function, (void*) message2);
    iret3 = pthread_create(&thread3, NULL, print_message_function, (void*) message3);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    printf("Thread 1 returns: %d\n", iret1);
    printf("Thread 2 returns: %d\n", iret2);
    printf("Thread 3 returns: %d\n", iret3);
    printf("val = %d\n", val);
                                                        // test futex
    if (pthread_create(&thread1, NULL, waiter, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    if (pthread_create(&thread2, NULL, waker, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    return 0;
}
