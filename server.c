#include <errno.h>
#include <bpf/libbpf.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <net/if.h>


#define PORT 8080

#define DRR_DEFAULT_QUANTUM_BYTES 1500

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

#define NSEC_PER_MSEC      1000000ULL
#define CODEL_TARGET_NS    (5ULL * NSEC_PER_MSEC)
#define CODEL_INTERVAL_NS  (100ULL * NSEC_PER_MSEC)

/* 10000 = 100.00% */
#define RWND_FACTOR_FULL 10000U
#define RWND_FACTOR_MIN  1U

struct codel_state {
	uint64_t first_above_time_ns;
	uint64_t drop_next_ns;

	uint32_t count;
	uint32_t last_count;

	bool dropping;
};

struct qval {
	char *msg;
	size_t length;
	size_t sent_offset;
	uint64_t enqueue_time_ns;
};

struct qnode {
	struct qnode *next;
	struct qval val;
};

/* One queue per accepted socket. */
struct queue {
	struct queue *next;

	struct qnode *head;
	struct qnode *tail;

	// some sockets stuff
	int socket_fd;
	uint32_t map_key;

	// some stuff for the DRR scheduler
	int64_t deficit;
	size_t quantum;

	// CoDel
	struct codel_state codel;

	// backpressure signal
	uint32_t rwnd_factor;

	// part of the scheduler stuff, kept at the end for stupid struct alignment as u know.
	bool peer_closed;
};

// lock the whole thing, use mutex even not RW.
struct multi_queue {
	struct queue *head;
	struct queue *current;

	pthread_mutex_t lock;
	pthread_cond_t wakeup;
};

struct scheduler_args {
	struct bpf_map *clients_map;
	struct multi_queue *queues;
};

struct client_args {
	struct multi_queue *queues;
	struct queue *flow;
};

static uint64_t monotonic_time_ns(void)
{
	struct timespec time;

	clock_gettime(CLOCK_MONOTONIC, &time);

	return (uint64_t)time.tv_sec * 1000000000ULL +
	(uint64_t)time.tv_nsec;
}

static struct queue *queue_create(
	int socket_fd,
	uint32_t map_key
)
{
	struct queue *queue = calloc(1, sizeof(*queue));

	if (!queue)
		return NULL;

	queue->socket_fd = socket_fd;
	queue->map_key = map_key;
	queue->quantum = DRR_DEFAULT_QUANTUM_BYTES;
	queue->rwnd_factor = RWND_FACTOR_FULL;

	return queue;
}

static void add_queue(
	struct multi_queue *queues,
	struct queue *queue
)
{
	pthread_mutex_lock(&queues->lock);

	queue->next = queues->head;
	queues->head = queue;

	if (!queues->current)
		queues->current = queue;

	pthread_mutex_unlock(&queues->lock);
}


static bool enqueue(
	struct multi_queue *queues,
	struct queue *queue,
	const void *msg,
	size_t length
)
{
	if (!msg || length == 0)
		return false;

	struct qnode *node = malloc(sizeof(*node));

	if (!node)
		return false;

	node->val.msg = malloc(length);

	if (!node->val.msg) {
		free(node);
		return false;
	}

	memcpy(node->val.msg, msg, length);

	node->val.length = length;
	node->val.sent_offset = 0;
	node->val.enqueue_time_ns = monotonic_time_ns();
	node->next = NULL;

	pthread_mutex_lock(&queues->lock);

	bool was_empty = queue->head == NULL;

	if (!was_empty) {
		queue->tail->next = node;
	}
	else {
		queue->head = node;
		pthread_cond_signal(&queues->wakeup);
	}

	// move tail ptr to the new tail
	queue->tail = node;

	pthread_mutex_unlock(&queues->lock);

	return true;
}

static struct qval *peek(struct queue *queue)
{
	if (!queue->head)
		return NULL;

	return &queue->head->val;
}

static void dequeue(struct queue *queue)
{
	struct qnode *node = queue->head;

	if (!node)
		return;

	queue->head = node->next;

	if (!queue->head)
		queue->tail = NULL;

	free(node->val.msg);
	free(node);
}

// DRR helper for selecting the next nonempty socket queue:

static struct queue *next_nonempty_queue(struct multi_queue *queues) {
	if (!queues->head)
		return NULL;

	struct queue *start;

	if (queues->current && queues->current->next)
		start = queues->current->next;
	else
		start = queues->head;

	struct queue *queue = start;

	do {
		if (queue->head)
			return queue;

		queue = queue->next;

		if (!queue)
			queue = queues->head;
	} while (queue != start);

	return NULL;
}

// return true when teh value of factor changes
bool codel_peek(struct queue *q, uint64_t now, uint32_t *factor) {
	uint64_t sojourn = now - q->head->val.enqueue_time_ns;

	uint64_t first_above_time_ns = q->codel.first_above_time_ns;

	uint32_t old_factor = *factor;
	uint32_t new_factor = old_factor;

	if (sojourn < CODEL_TARGET_NS) {
		q->codel.first_above_time_ns = 0;
		q->codel.dropping = false;

		if (old_factor < RWND_FACTOR_FULL) {
			uint32_t increase = max(old_factor / 20U, 1U);

			new_factor = min(old_factor + increase, RWND_FACTOR_FULL);
		}
	} else {
		if (first_above_time_ns == 0) {
			q->codel.first_above_time_ns = now + CODEL_INTERVAL_NS;
		} else if (now >= first_above_time_ns) {
			q->codel.dropping = true;
		}
	}

	if (q->codel.dropping && now >= q->codel.drop_next_ns) {
		uint32_t decrease = max(new_factor / 20U, 1U);

		new_factor = max(new_factor - decrease, RWND_FACTOR_MIN);

		q->codel.drop_next_ns = now + CODEL_INTERVAL_NS / sqrt(++q->codel.count);
	}

	*factor = new_factor;

	return new_factor != old_factor;
}

static void *scheduler(void *arg)
{
	struct scheduler_args *args = arg;

	struct bpf_map *map = args->clients_map;
	struct multi_queue *queues = args->queues;

	free(args);

	for (;;) {
		pthread_mutex_lock(&queues->lock);

		struct queue *queue = next_nonempty_queue(queues);

		while (!queue) {
			pthread_cond_wait(
				&queues->wakeup,
				&queues->lock
			);

			queue = next_nonempty_queue(queues);
		}

		queue->deficit += queue->quantum;

		for (;;) {
			struct qval *response = peek(queue);

			if (!response)
				break;

			size_t remaining = response->length - response->sent_offset;

			if (remaining > (size_t)queue->deficit)
				break;

			if (response->sent_offset == 0) {
				uint32_t factor = queue->rwnd_factor;

				if (codel_peek(queue, monotonic_time_ns(), &factor)) {
					int error = bpf_map__update_elem(
						map,
						&queue->map_key,
						sizeof(queue->map_key),
						&factor,
						sizeof(factor),
						BPF_ANY
					);

					if (error == 0)
						queue->rwnd_factor = factor;
				}
			}

			ssize_t sent = send(
				queue->socket_fd,
				response->msg + response->sent_offset,
				remaining,
				MSG_DONTWAIT | MSG_NOSIGNAL
			);

			if (sent > 0) {
				response->sent_offset += (size_t)sent;
				queue->deficit -= sent;

				if (response->sent_offset == response->length)
					dequeue(queue);

				continue;
			}

			if (sent < 0 && errno == EINTR)
				continue;

			if (sent < 0 &&
				(errno == EAGAIN || errno == EWOULDBLOCK)) {
				queue->deficit = 0;
				break;
			}

			queue->peer_closed = true;

			while (queue->head)
				dequeue(queue);

			queue->deficit = 0;

			if (queue->socket_fd >= 0) {
				close(queue->socket_fd);
				queue->socket_fd = -1;
			}

			break;
		}

		if (!queue->head) {
			queue->deficit = 0;

			if (queue->peer_closed && queue->socket_fd >= 0) {
				close(queue->socket_fd);
				queue->socket_fd = -1;
			}
		}

		queues->current = queue;

		pthread_mutex_unlock(&queues->lock);
	}

	return NULL;
}

void* handle_client(void* arg) {
	struct client_args *args = arg;

	struct multi_queue *queues = args->queues;
	struct queue *flow = args->flow;

	free(args);

	int socket_fd = flow->socket_fd;

	char buffer[1024] = { 0 };

	ssize_t valread;

	for(;;) {
		ssize_t n = read(socket_fd, buffer, sizeof(buffer) - 1);
		if (n <= 0) break;         /* EOF or error */

		// send(socket_fd, buffer, (size_t)n, 0); // enqueue instead of sending.
		enqueue(
			queues,
			flow,
			buffer,
			(size_t)n
		);
	}

	pthread_mutex_lock(&queues->lock);

	flow->peer_closed = true;

	if (!flow->head && flow->socket_fd >= 0) {
		close(flow->socket_fd);
		flow->socket_fd = -1;
	} else {
		pthread_cond_signal(&queues->wakeup);
	}

	pthread_mutex_unlock(&queues->lock);

	return NULL;
}

static void *handle_client_direct(void *arg)
{
	struct client_args *args = arg;
	struct queue *flow = args->flow;
	int socket_fd = flow->socket_fd;

	free(args);

	char buffer[1024];

	for (;;) {
		ssize_t received = read(socket_fd, buffer, sizeof(buffer));

		if (received <= 0)
			break;

		size_t sent = 0;

		while (sent < (size_t)received) {
			ssize_t result = send(
				socket_fd,
				buffer + sent,
				(size_t)received - sent,
				MSG_NOSIGNAL
			);

			if (result > 0) {
				sent += (size_t)result;
				continue;
			}

			if (result < 0 && errno == EINTR)
				continue;

			break;
		}
	}

	close(socket_fd);
	flow->socket_fd = -1;

	return NULL;
}

int main(int argc, char const* argv[])
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);

	// failed expierment #1: congestion algorithm works on cwnd, not rwnd.
	/*if (setsockopt(server_fd, IPPROTO_TCP, TCP_CONGESTION, "my_algo", sizeof("my_algo")) < 0) {*/
	/*	perror("TCP_CONGESTION");*/
	/*	exit(EXIT_FAILURE);*/
	/*}*/

	// Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

	// load that map
	// populate the map with a new entry on each accept

	// load object
	// load map
	// attach that bitch

	struct bpf_object *obj;
  struct bpf_program *prog;
	struct bpf_map *map;

	// find the object
	// if program:
	//    find the program
	//    load the object
	//    attach the program
	// if map:
	// find the map by name
	// if it's a normal hashmap, not ring buffer, you are ready to go.
	obj = bpf_object__open_file("./out/stall.bpf.o", NULL);
	if (!obj)
		return 1;

	if (bpf_object__load(obj)) // for CO-RE
		goto fail;

	prog = bpf_object__find_program_by_name(obj, "stall");
	if (!prog) {
		fprintf(stderr, "could not find BPF program 'stall'\n");
		goto fail;
	}

	// this should be doing what this does. afaik
	// sudo tc filter add dev lo egress bpf obj ./out/stall.bpf.o sec tc direct-action
	int lo_ifindex = if_nametoindex("lo");
	if (!lo_ifindex) {
		perror("if_nametoindex");
		goto fail;
	}

	struct bpf_tc_hook tc_hook = {
		.sz = sizeof(tc_hook),
		.ifindex = lo_ifindex,
		.attach_point = BPF_TC_EGRESS,
	};

	int error = bpf_tc_hook_create(&tc_hook);

	if (error && error != -EEXIST) {
		fprintf(stderr, "could not create clsact: %s\n", strerror(-error));
		goto fail;
	}

	struct bpf_tc_opts tc_opts = {
		.sz = sizeof(tc_opts),
		.prog_fd = bpf_program__fd(prog),
		.handle = 1,
		.priority = 1,
		.flags = BPF_TC_F_REPLACE,
	};

	error = bpf_tc_attach(&tc_hook, &tc_opts);

	if (error) {
		fprintf(stderr, "could not attach TC program: %s\n", strerror(-error));
		goto fail;
	}

	// KV map of (struct sockaddr*, rwnd scale factor (int))
	map = bpf_object__find_map_by_name(obj, "clients_map");

	// since accepting loop never stops.
	// we have to define the multi_queue before it
	// spawn the scheduler thread
	// and that's it.

	struct multi_queue *mqueue = calloc(1, sizeof(*mqueue));

	pthread_mutex_init(&mqueue->lock, NULL);
	pthread_cond_init(&mqueue->wakeup, NULL);


	pthread_t scheduler_thread;

	struct scheduler_args *socket_args = malloc(sizeof(*socket_args));

	if (!socket_args)
		goto fail;

	socket_args->clients_map = map;
	socket_args->queues = mqueue;


	// we pass the map and multiqueue to it.
	if (pthread_create(&scheduler_thread, NULL, scheduler, socket_args) != 0) {
		perror("pthread_create");
		// this is not a double free, if it errors, then those two calls, which we do in the `scheduler` just won't get called.
		free(socket_args);
	} else {
		pthread_detach(scheduler_thread);
	}

	for(;;) {
		if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
			perror("accept");
			continue;
		}

		// POPULATE MAP
		uint32_t client_port = ntohs(address.sin_port);
		uint32_t scale_factor = RWND_FACTOR_FULL;

		bpf_map__update_elem(map, &client_port, sizeof(client_port), &scale_factor, sizeof(scale_factor), BPF_ANY);

		pthread_t thread;

		struct queue *flow = queue_create(
			new_socket,
			client_port
		);

		if (!flow) {
			close(new_socket);
			continue;
		}

		add_queue(mqueue, flow);

		struct client_args *socket_args = malloc(sizeof(*socket_args));

		if (!socket_args) {
			close(new_socket);
			continue;
		}

		socket_args->queues = mqueue;
		socket_args->flow = flow;

		if (pthread_create(&thread, NULL, handle_client, socket_args) != 0) {
			perror("pthread_create");
			// this is not a double free, if it errors, then those two calls, which we do in the `handle_client()` just won't get called.
			free(socket_args);
			close(new_socket);
		} else {
			pthread_detach(thread);
		}
	}

fail:
	bpf_object__close(obj);
   
    // closing the listening socket
    close(server_fd);
    return 0;
}
