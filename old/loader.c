#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

struct evt_tcp_connect {
	__u32 saddr;
	__u16 sport;
	__u16 dport;
	__u32 daddr;
	pid_t pid;
};

struct ring_buffer *rb;

static int handle_event(void *ctx, void *data, size_t size)
{
	char daddr[INET_ADDRSTRLEN];
	char saddr[INET_ADDRSTRLEN];

	struct evt_tcp_connect *e = data;

	inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));
	inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));

	printf("pid=%d saddr=%s sport=%d dport=%d daddr=%s\n", e->pid, saddr, e->sport, e->dport, daddr);
	return 0;
}

int main(int argc, char **argv) {
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	pid_t pid;

	if (argc < 2)
		return 1;

	obj = bpf_object__open_file("out/tracer.bpf.o", NULL);
	if (!obj)
		return 1;
	
	prog = bpf_object__find_program_by_name(obj, "cubic_after");
	if (!prog)
		goto fail;


	if (bpf_object__load(obj)) // for CO-RE
		goto fail;

	link = bpf_program__attach(prog);
	if (!link)
		goto fail;

	pid = fork();
	if (pid < 0)
		goto detach;

	if (pid == 0) { // code to run in the new fork.
		execv(argv[1], &argv[1]);
		_exit(127);
	}

	printf("HERE PID=%d, NEW PID=%d\n", getpid(), pid);

    /* Create ring buffer consumer */
    rb = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(obj, "rb_map")), handle_event, NULL, NULL);

	// Poll: calls handle_event for each available record
	// and close once the server closes
    while (1) {
		pid_t r = waitpid(pid, NULL, WNOHANG);

		if(r == pid) {
			ring_buffer__free(rb);
			goto detach;
		}

        ring_buffer__poll(rb, 100);
    }

detach:
	bpf_link__destroy(link);
fail:
	bpf_object__close(obj);

	return 0;
}
