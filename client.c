#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PORT 8080
#define CLIENT_COUNT 10
#define BULK_CLIENT_COUNT 8
#define BULK_CHUNK_COUNT 2048
#define BULK_CHUNK_SIZE (64 * 1024)
#define INTERACTIVE_ROUNDS 10000
#define INTERACTIVE_MESSAGE_SIZE 256
#define RECOVERY_ROUNDS 500
#define RECOVERY_MESSAGE_SIZE 256

static pthread_barrier_t start_barrier;
static pthread_barrier_t recovery_barrier;

struct drain_state {
	int socket_fd;
	size_t received_bytes;
	int closed;
	pthread_mutex_t lock;
	pthread_cond_t wakeup;
};

static uint64_t monotonic_time_ns(void)
{
	struct timespec time;

	clock_gettime(CLOCK_MONOTONIC, &time);

	return (uint64_t)time.tv_sec * 1000000000ULL +
		(uint64_t)time.tv_nsec;
}

static int send_all(int socket_fd, const void *buffer, size_t length)
{
	const char *bytes = buffer;
	size_t sent = 0;

	while (sent < length) {
		ssize_t result = send(
			socket_fd,
			bytes + sent,
			length - sent,
			MSG_NOSIGNAL
		);

		if (result > 0) {
			sent += (size_t)result;
			continue;
		}

		if (result < 0 && errno == EINTR)
			continue;

		return 0;
	}

	return 1;
}

static int receive_all(int socket_fd, void *buffer, size_t length)
{
	char *bytes = buffer;
	size_t received = 0;

	while (received < length) {
		ssize_t result = recv(
			socket_fd,
			bytes + received,
			length - received,
			0
		);

		if (result > 0) {
			received += (size_t)result;
			continue;
		}

		if (result < 0 && errno == EINTR)
			continue;

		return 0;
	}

	return 1;
}

static void *drain_responses(void *arg)
{
	struct drain_state *state = arg;
	char buffer[4096];
	ssize_t received;

	while ((received = recv(
		state->socket_fd,
		buffer,
		sizeof(buffer),
		0
	)) > 0) {
		pthread_mutex_lock(&state->lock);
		state->received_bytes += (size_t)received;
		pthread_cond_broadcast(&state->wakeup);
		pthread_mutex_unlock(&state->lock);
	}

	pthread_mutex_lock(&state->lock);
	state->closed = 1;
	pthread_cond_broadcast(&state->wakeup);
	pthread_mutex_unlock(&state->lock);

	return NULL;
}

static int wait_for_responses(struct drain_state *state, size_t expected_bytes)
{
	pthread_mutex_lock(&state->lock);

	while (state->received_bytes < expected_bytes && !state->closed)
		pthread_cond_wait(&state->wakeup, &state->lock);

	int received_everything = state->received_bytes >= expected_bytes;

	pthread_mutex_unlock(&state->lock);

	return received_everything;
}

static void run_bulk_client(int client_fd, uintptr_t client_number)
{
	char message[BULK_CHUNK_SIZE];
	char recovery_message[RECOVERY_MESSAGE_SIZE];
	size_t sent_bytes = 0;
	size_t recovery_bytes = 0;
	pthread_t reader;
	struct drain_state drain = {
		.socket_fd = client_fd,
	};

	memset(message, 'B', sizeof(message));
	memset(recovery_message, 'R', sizeof(recovery_message));

	pthread_mutex_init(&drain.lock, NULL);
	pthread_cond_init(&drain.wakeup, NULL);
	pthread_create(&reader, NULL, drain_responses, &drain);

	for (int i = 0; i < BULK_CHUNK_COUNT; i++) {
		if (!send_all(client_fd, message, sizeof(message))) {
			perror("bulk send");
			break;
		}

		sent_bytes += sizeof(message);
	}

	printf(
		"bulk client %lu sent %zu bytes\n",
		client_number,
		sent_bytes
	);

	pthread_barrier_wait(&recovery_barrier);

	if (!wait_for_responses(&drain, sent_bytes))
		fprintf(stderr, "bulk client %lu closed while draining\n", client_number);

	printf("bulk client %lu starting recovery probes\n", client_number);

	for (int i = 0; i < RECOVERY_ROUNDS; i++) {
		if (!send_all(
			client_fd,
			recovery_message,
			sizeof(recovery_message)
		)) {
			perror("recovery send");
			break;
		}

		recovery_bytes += sizeof(recovery_message);

		struct timespec delay = {
			.tv_sec = 0,
			.tv_nsec = 10 * 1000000L,
		};

		nanosleep(&delay, NULL);
	}

	if (wait_for_responses(&drain, sent_bytes + recovery_bytes))
		printf("bulk client %lu finished recovery probes\n", client_number);

	shutdown(client_fd, SHUT_WR);
	pthread_join(reader, NULL);

	pthread_cond_destroy(&drain.wakeup);
	pthread_mutex_destroy(&drain.lock);
}

static void run_interactive_client(int client_fd, uintptr_t client_number)
{
	char message[INTERACTIVE_MESSAGE_SIZE];
	char response[INTERACTIVE_MESSAGE_SIZE];
	uint64_t total_latency_ns = 0;
	uint64_t maximum_latency_ns = 0;
	int completed = 0;

	memset(message, 'I', sizeof(message));

	for (int i = 0; i < INTERACTIVE_ROUNDS; i++) {
		uint64_t start = monotonic_time_ns();

		if (!send_all(client_fd, message, sizeof(message)) ||
			!receive_all(client_fd, response, sizeof(response))) {
			perror("interactive request");
			break;
		}

		uint64_t latency = monotonic_time_ns() - start;

		total_latency_ns += latency;
		if (latency > maximum_latency_ns)
			maximum_latency_ns = latency;

		completed++;
	}

	if (completed > 0) {
		printf(
			"interactive client %lu: average %.3f ms, max %.3f ms\n",
			client_number,
			(double)total_latency_ns / completed / 1000000.0,
			(double)maximum_latency_ns / 1000000.0
		);
	}
}

static void *run_client(void *arg)
{
	uintptr_t client_number = (uintptr_t)arg;
	int client_fd;
	struct sockaddr_in server_address = { 0 };

	client_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (client_fd < 0) {
		perror("socket");
		return NULL;
	}

	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(PORT);

	if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0) {
		fprintf(stderr, "invalid server address\n");
		close(client_fd);
		return NULL;
	}

	if (connect(
		client_fd,
		(struct sockaddr *)&server_address,
		sizeof(server_address)
	) < 0) {
		perror("connect");
		close(client_fd);
		return NULL;
	}

	pthread_barrier_wait(&start_barrier);

	if (client_number < BULK_CLIENT_COUNT)
		run_bulk_client(client_fd, client_number);
	else
		run_interactive_client(client_fd, client_number);

	close(client_fd);

	return NULL;
}

int main(void)
{
	pthread_t clients[CLIENT_COUNT];

	pthread_barrier_init(&start_barrier, NULL, CLIENT_COUNT);
	pthread_barrier_init(&recovery_barrier, NULL, BULK_CLIENT_COUNT);

	for (uintptr_t i = 0; i < CLIENT_COUNT; i++) {
		if (pthread_create(&clients[i], NULL, run_client, (void *)i) != 0) {
			perror("pthread_create");
			return 1;
		}
	}

	for (int i = 0; i < CLIENT_COUNT; i++)
		pthread_join(clients[i], NULL);

	pthread_barrier_destroy(&start_barrier);
	pthread_barrier_destroy(&recovery_barrier);

	return 0;
}
