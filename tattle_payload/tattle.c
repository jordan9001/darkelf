#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

// helper declarations
static int mirror_stdin();
static void* listener(void* fds);

// static vars
static pthread_t lthread;

int mirror_stdin() {
	int input_fd;
	int inpipe_fd[2];
	int* thread_fds;

	// duplicate the handles
	input_fd = dup(STDIN_FILENO);
	if (input_fd == -1) {
		return -1;
	}
	
	// create pipes
	if (pipe(inpipe_fd)) {
		// bad bad not good
		return -1;
	}

	// replace std fds
	if (dup2(inpipe_fd[0], STDIN_FILENO) == -1) {
		return -1;
	}
	close(inpipe_fd[0]);

	// start the listener thread
	thread_fds = (int*)malloc(sizeof(int) * 2);
	if (thread_fds == NULL) {
		return -1;
	}
	thread_fds[0] = inpipe_fd[1]; // the fd to write to
	thread_fds[1] = input_fd; // the fd to read from

	if (pthread_create(&lthread, NULL, listener, (void*)thread_fds)) {
		return -1;
	}
	return 0;
}

#define LISTEN_BUFSIZE	4096
// The listening thread that is in the middle of input
void* listener(void* fds) {
	int inputfd;
	int outputfd;
	char buf[LISTEN_BUFSIZE];
	char* bufptr;
	ssize_t incount;
	ssize_t outcount;

	inputfd = ((int*)fds)[1];
	outputfd = ((int*)fds)[0];

	while (1) {
		// get input
		incount = read(inputfd, buf, LISTEN_BUFSIZE);
		if (incount == 0) {
			break;
		}
		printf("Read in %zd %s\n", incount, buf);

		// send out
		bufptr = buf;
		while (incount) {
			outcount = write(outputfd, bufptr, incount);
			if (outcount == 0) {
				break;
			}
			incount -= outcount;
			bufptr += outcount;		
		}
	}
	
	// cleanup
	free(fds);
	dup2(inputfd, STDIN_FILENO);
	close(inputfd);
	close(outputfd);

	return NULL;
}

void thrd_main() {

	if (mirror_stdin()) {
		printf("Could not mirror stdin: %d : %s\n", errno, strerror(errno));
		exit(-1);
	}

	// return to the real main
}

void main() {
	// if we get called as an executable, we need to do the following:
	// set up all the file descriptor stuff
	// fork
	// in child execve: file descriptors are preserved across execve
	// in parent, just keep the thread going, wait on that I guess
	// TODO
}
