#include <bpf/libbpf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	return vfprintf(stderr, fmt, ap);
}

int main(int argc, char **argv) {
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	char log_buf[64 * 1024] = {};
	char errmsg[256];
	int err;

	libbpf_set_print(libbpf_print);

	obj = bpf_object__open_file("out/stall.bpf.o", NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open_file failed: %s\n", strerror(-err));
		return 1;
	}
	if (!obj) {
		fprintf(stderr, "open_file failed: NULL (errno=%d: %s)\n",
			errno, strerror(errno));
		return 1;
	}

	prog = bpf_object__find_program_by_name(obj, "rwnd");
	if (!prog) {
		struct bpf_program *p;

		fprintf(stderr, "no program named 'rwnd'; available programs:\n");
		bpf_object__for_each_program(p, obj)
			fprintf(stderr, "  - %s\n", bpf_program__name(p));
		goto fail;
	}

	bpf_program__set_log_buf(prog, log_buf, sizeof(log_buf));
	bpf_program__set_log_level(prog, 1);

	err = bpf_object__load(obj);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "load failed: %s\n", errmsg);
		if (log_buf[0])
			fprintf(stderr, "--- verifier log ---\n%s\n", log_buf);
		goto fail;
	}

	link = bpf_program__attach(prog);
	err = libbpf_get_error(link);
	if (err) {
		libbpf_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "attach failed: %s\n", errmsg);
		goto fail;
	}

	printf("attached 'rwnd'; press Ctrl-C to stop\n");
	for (;;)
		pause();

	bpf_link__destroy(link);
fail:
	bpf_object__close(obj);

	return 0;
}
