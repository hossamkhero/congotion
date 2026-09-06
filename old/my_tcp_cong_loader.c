#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

static volatile sig_atomic_t exiting;

static void handle_signal(int signo)
{
	exiting = 1;
}

static int unregister_my_algo(void)
{
	__u32 id = 0;
	__u32 next_id;

	while (bpf_map_get_next_id(id, &next_id) == 0) {
		struct bpf_map_info info = {};
		__u32 info_len = sizeof(info);
		int fd;

		id = next_id;
		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0)
			continue;

		if (bpf_map_get_info_by_fd(fd, &info, &info_len) == 0 &&
			info.type == BPF_MAP_TYPE_STRUCT_OPS &&
			strcmp(info.name, "my_algo") == 0) {
			int zero = 0;
			int err = bpf_map_delete_elem(fd, &zero);

			close(fd);
			return err;
		}

		close(fd);
	}

	return -1;
}

int main(int argc, char **argv) {
	struct bpf_object *obj;
	struct bpf_map *map;
	struct bpf_link *link;

	if(argc > 1 && strcmp(argv[1], "unregister") == 0) {
		unregister_my_algo();
		return 0;
	}

	obj = bpf_object__open_file("out/my_tcp_cong.bpf.o", NULL);
	if (!obj)
		return 1;

	if (bpf_object__load(obj)) {
		fprintf(stderr, "failed to load BPF object\n");
		goto fail;
	}

	map = bpf_object__find_map_by_name(obj, "my_algo");
	if (!map)

		goto fail;

	link = bpf_map__attach_struct_ops(map);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "failed to attach struct_ops\n");
		link = NULL;
		goto fail;
	}

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	// need to not leave.
	printf("my_algo registered; press Ctrl-C to stop\n");

	while (!exiting)
		pause();

	bpf_link__destroy(link);
	bpf_object__close(obj);

fail:
	bpf_object__close(obj);

	return 0;
}
