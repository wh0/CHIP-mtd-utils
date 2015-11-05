#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <mtd/ubi-user.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <poll.h>
#include <sys/timerfd.h>
#include <inttypes.h>

#include <getopt.h>
#include <libubi.h>

#include "list.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#ifndef NDEBUG
#define _log(lvl, M, ...) __log(lvl, "[%s:%d] " M, __FILE__, __LINE__, ##__VA_ARGS__);
#else
#define _log(lvl, M, ...) __log(lvl, M, ##__VA_ARGS__);
#endif
#define log(M, ...) _log(2, M, ##__VA_ARGS__);
#define log_fatal(M, ...) _log(0, "[FATAL]" M, ##__VA_ARGS__);
#define log_err(M, ...) _log(1, "[ERR]" M, ##__VA_ARGS__);
#define log_warn(M, ...) _log(2, "[WARN]" M, ##__VA_ARGS__);
#define log_info(M, ...) _log(3, "[INFO]" M, ##__VA_ARGS__);
#define log_debug(M, ...) _log(4, "[DEBUG]" M, ##__VA_ARGS__);


int log_level;

static void __log(int level, const char *fmt, ...)
{
	va_list ap;
	if (level > log_level)
		return;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

static const uint64_t UBIHEALTHD_MAGIC_VERSION = 0x00000001LLU;

/*
 * Basic algorithm:
 *  - get number of PEBs and identify sleep times between scheduling
 *  - read stats to identify hotspots (schedule full block read if identified as such)
 *  - read PEB and remove from list (move to tail ?)
 */

static const char opt_string[] = "d:f:hr:s:x:v:";
static const struct option options[] = {
	{
		.name = "device",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'd'
	},
	{
		.name = "file",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'f'
	},
	{
		.name = "read_complete",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'r'
	},
	{
		.name = "scrub_complete",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 's'
	},
	{
		.name = "read_threshold",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'x'
	},
	{
		.name = "help",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'h'
	},
	{
		.name = "verbosity",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'v'
	}
};

struct peb_info {
	int64_t peb_num;
	uint64_t err_cnt;
	uint64_t read_cnt;
	uint64_t prev_read_cnt;
	time_t last_stat_update;
	time_t last_read;
	time_t last_err;
} __attribute__((packed));

typedef enum {
	SCHED_READ,
	SCHED_SCRUB
} sched_type;

struct sched_peb {
	struct peb_info *peb;
	sched_type type;
	struct list_head list;
};

struct peb_list {
	struct peb_info *peb;
	struct list_head list;
};

static const char *help_str = \
"[OPTIONS]\n" \
"  -h, --help\t\tShow this message and exit\n" \
"  -d, --device\t\tDevice to be monitored (default: /dev/ubi0)\n" \
"  -f, --file\t\tPath to statistics save file\n" \
"  -r, --read_complete\tTimeframe for reading all PEBs in seconds\n" \
"  -s, --scrub_complete\tTimeframe for scrubbing all PEBs in seconds\n" \
"  -x, --read_threshold\tNumber of reads between two stats updates\n" \
"                      \twhich will trigger a PEB read\n" \
"  -v, --verbosity\t\tlog level (0-4)\n";

static void usage(const char* progname)
{
	printf("usage: %s [OPTIONS]", progname);
	printf("\n%s\n", help_str);
	_exit(1);
}

static int64_t get_num_pebs(const char *ubi_dev)
{
	libubi_t libubi = libubi_open();
	struct ubi_dev_info dev_info;
	int err;
	err = ubi_get_dev_info(libubi, ubi_dev, &dev_info);
	if (err) {
		log_err("Could not get ubi info for device %s", ubi_dev);
		return -1;
	}
	libubi_close(libubi);
	return dev_info.total_lebs;
}

static int write_stats_file(const char *filename, struct peb_list *peb_head, struct sched_peb *sched_read_head, struct sched_peb *sched_scrub_head, int pnum)
{
	int64_t next_read_peb = 0;
	int64_t next_scrub_peb = 0;
	struct peb_info *peb = NULL;
	struct peb_list *tmpp = NULL;
	struct sched_peb *p = NULL;
	FILE *file = fopen(filename, "wb");
	if (file == NULL)
		return -1;
	p = list_first_entry_or_null(&sched_read_head->list, struct sched_peb, list);
	if (p)
		next_read_peb = p->peb->peb_num;
	p = list_first_entry_or_null(&sched_scrub_head->list, struct sched_peb, list);
	if (p)
		next_scrub_peb = p->peb->peb_num;
	fwrite(&UBIHEALTHD_MAGIC_VERSION, sizeof(UBIHEALTHD_MAGIC_VERSION), 1, file);
	fwrite(&pnum, sizeof(pnum), 1, file);
	fwrite(&next_read_peb, sizeof(next_read_peb), 1, file);
	fwrite(&next_scrub_peb, sizeof(next_scrub_peb), 1, file);
	list_for_each_entry(tmpp, &peb_head->list, list) {
		peb = tmpp->peb;
		fwrite(peb, sizeof(struct peb_info), 1, file);
	}
	fclose(file);
	return 0;
}


static int init_stats(int fd, struct list_head *head, int pnum)
{
	int i, err = 0;
	size_t req_size = pnum * sizeof(struct ubi_stats_entry);
	struct ubi_stats_req *req = malloc(sizeof(struct ubi_stats_req) + req_size);
	if (!req) {
		log_err("Could not alloc ubi_stats_req: %s", strerror(errno));
		return -1;
	}
	req->req_len = req_size + sizeof(struct ubi_stats_req);
	req->req_pnum = -1;
	err = ioctl(fd, UBI_IOCSTATS, req);
	if (err < 0) {
		log_err("Could not init stats via ioctl: %s", strerror(errno));
		free(req);
		return -1;
	}
	log_info("Kernel reported stats for %d PEBs", err);
	struct peb_info *peb = NULL;
	struct peb_list *p = NULL;
	time_t now = time(NULL);
	for (i = 0; i < err; i++) {
		struct ubi_stats_entry *s = &req->stats[i];
		peb = malloc(sizeof(struct peb_info));
		if (!peb) {
			log_err("Could not alloc peb_info");
			free(req);
			return -1;
		}
		peb->peb_num = s->pnum;
		peb->err_cnt = s->ec;
		peb->read_cnt = s->rc;
		peb->prev_read_cnt = s->rc;
		peb->last_stat_update = now;
		p = malloc(sizeof(struct peb_list));
		if (!p) {
			log_err("Could not alloc peb_list element");
			free(req);
			return -1;
		}
		p->peb = peb;
		list_add_tail(&p->list, head);
	}
	free(req);
	return 0;
}

static void free_list(struct peb_list *head)
{
	if (list_empty(&head->list))
		return;
	struct peb_list *p = NULL;
	struct peb_list *tmp = NULL;
	list_for_each_entry_safe(p, tmp, &head->list, list) {
		list_del(&p->list);
		free(p->peb);
		free(p);
	}
}

static int update_stats(int fd, struct peb_list *head, int pnum)
{
	if (list_empty(&head->list)) {
		log_fatal("PEB list not initialized");
		return -1;
	}
	int i, err = 0;
	size_t req_size = pnum * sizeof(struct ubi_stats_entry);
	struct ubi_stats_req *req = malloc(sizeof(struct ubi_stats_req) + req_size);
	if (!req) {
		log_err("Could not alloc ubi_stats_req: %s", strerror(errno));
		return -1;
	}
	memset(req, 0, sizeof(struct ubi_stats_req));
	req->req_len = req_size + sizeof(struct ubi_stats_req);
	req->req_pnum = -1;
	log_debug("req_len: %d, req_pnum: %d", req->req_len, req->req_pnum);
	err = ioctl(fd, UBI_IOCSTATS, req);
	if (err < 0) {
		log_err("Could not get stats for PEBs, [%d] %s", errno, strerror(errno));
		free(req);
		return -1;
	}
	log_debug("Kernel reported stats for %d PEBs", err);
	time_t now = time(NULL);
	for (i = 0; i < err; i++) {
		struct ubi_stats_entry *s = &req->stats[i];
		struct peb_list *p = NULL;
		struct peb_info *peb = NULL;
		list_for_each_entry(p, &head->list, list) {
			if (p->peb && (p->peb->peb_num == s->pnum)) {
				peb = p->peb;
				break;
			}
		}
		if (!peb) {
			log_warn("Could not get stats for PEB %d", i);
			continue;
		}
		/* TODO(sahne): check for overflow ! */
		peb->err_cnt = s->ec;
		peb->prev_read_cnt = peb->read_cnt;
		peb->read_cnt = s->rc;
		/* check if peb was erased (read_cnt would be reset to 0 if it was) */
		if (peb->read_cnt < peb->prev_read_cnt)
			peb->prev_read_cnt = peb->read_cnt;
		peb->last_stat_update = now;
	}
	free(req);
	return 0;
}

static int read_peb(int fd, struct peb_info *peb)
{
	time_t now = time(NULL);
	log_debug("Reading PEB %"PRIu64 , peb->peb_num);
	int err = ioctl(fd, UBI_IOCRPEB, &peb->peb_num);
	if (err < 0) {
		log_err("Error while reading PEB %" PRIu64, peb->peb_num);
		return -1;
	}
	peb->last_read = now;
	return 0;
}

static int scrub_peb(int fd, struct peb_info *peb)
{
	time_t now = time(NULL);
	log_debug("Scrubbing PEB %"PRIu64, peb->peb_num);
	int err = ioctl (fd, UBI_IOCSPEB, &peb->peb_num);
	if (err < 0) {
		log_err("Error while scrubbing PEB %" PRIu64, peb->peb_num);
		return -1;
	}
	peb->last_read = now;
	return 0;
}

static int schedule_peb(struct list_head *sched_list, struct peb_info *peb, sched_type type)
{
	struct sched_peb *s = malloc(sizeof(struct sched_peb));
	if (!s) {
		log_err("Could not allocate memory");
		return -1;
	}
	s->peb = peb;
	s->type = type;
	list_add_tail(&s->list, sched_list);
	return 0;
}

static int work(struct sched_peb *sched_list, int fd)
{
	if (list_empty(&sched_list->list))
		return 0;
	struct sched_peb *sched = list_first_entry(&sched_list->list, struct sched_peb, list);
	struct peb_info *peb = sched->peb;
	if (peb == NULL) {
		log_warn("invalid peb");
		return -1;
	}
	/* delete entry from list, we will add it if needed */
	list_del(&sched->list);
	switch(sched->type) {
	case SCHED_READ:
		read_peb(fd, peb);
		break;
	case SCHED_SCRUB:
		scrub_peb(fd, peb);
		break;
	default:
		log_warn("Unknown work type: %d", sched->type);
		free(sched);
		return -1;
	}
	/* reschedule PEB */
	/* TODO(sahne): check error read/scrub in case PEB went bad (so we don't reschedule it) */
	schedule_peb(&sched_list->list, peb, sched->type);
	free(sched);
	return 1;
}

static int create_and_arm_timer(int seconds)
{
	int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (tfd < 0) {
		log_err("Could not create timer");
		return -1;
	}
	struct itimerspec tspec = {
		.it_interval = {
			.tv_sec = seconds,
			.tv_nsec = 0,
		},
		.it_value = {
			.tv_sec = 0,
			.tv_nsec = 1,
		},
	};
	if (timerfd_settime(tfd, 0, &tspec, NULL) < 0) {
		log_err("Could not arm timer");
		close(tfd);
		return -1;
	}

	return tfd;
}

static int read_stats_file(const char *filename, struct peb_list *peb_head, struct sched_peb *sched_read_head, struct sched_peb *sched_scrub_head)
{
	int num_pebs = 0;
	int64_t next_read_peb;
	int64_t next_scrub_peb;
	uint64_t magic_version;
	FILE *file = fopen(filename, "rb");
	ssize_t i;
	if (file == NULL)
		return -1;
	fread(&magic_version, sizeof(magic_version), 1, file);
	if (magic_version != UBIHEALTHD_MAGIC_VERSION) {
		log_warn("Magic mismatching, aborting reading from stats file");
		fclose(file);
		return -1;
	}
	fread(&num_pebs, sizeof(num_pebs), 1, file);
	fread(&next_read_peb, sizeof(next_read_peb), 1, file);
	fread(&next_scrub_peb, sizeof(next_scrub_peb), 1, file);
	for (i = 0; i < num_pebs; i++) {
		struct peb_info *peb = malloc(sizeof(struct peb_info));
		if (!peb) {
			log_err("Could not allocate peb_info");
			return -1;
		}
		struct peb_list *p = NULL;
		fread(peb, sizeof(struct peb_info), 1, file);
		list_for_each_entry(p, &peb_head->list, list) {
			if (p->peb && (p->peb->peb_num == peb->peb_num)) {
				free(p->peb);
				p->peb = peb;
			}
		}
	}
	/* init read and scrub lists */
	struct peb_list *p = NULL;
	list_for_each_entry(p, &peb_head->list, list) {
		if (p->peb->peb_num >= next_read_peb)
			schedule_peb(&sched_read_head->list, p->peb, SCHED_READ);
		if (p->peb->peb_num >= next_scrub_peb)
			schedule_peb(&sched_scrub_head->list, p->peb, SCHED_SCRUB);
	}
	p = NULL;
	list_for_each_entry(p, &peb_head->list, list) {
		if (p->peb->peb_num < next_read_peb)
			schedule_peb(&sched_read_head->list, p->peb, SCHED_READ);
		if (p->peb->peb_num < next_scrub_peb)
			schedule_peb(&sched_scrub_head->list, p->peb, SCHED_SCRUB);
	}

	return 0;
}

static int init_sigfd()
{
	int sigfd;
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGUSR1);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		log_warn("Could not init sigprocmask");
		return -1;
	}
	sigfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
	if (sigfd < 0) {
		log_warn("Could not init signal handling");
		return -1;
	}
	return sigfd;
}

int main(int argc, char **argv)
{
	int c, i;
	int64_t num_pebs;
	time_t read_completion = 100000;
	time_t scrub_completion = 1000000;
	uint64_t read_threshold = 10000;
	struct sched_peb *sched_read_head;
	struct sched_peb *sched_scrub_head;
	struct peb_list *peb_head;
	const char *stats_file = "/tmp/ubihealth_stats";
	const char *ubi_dev = "/dev/ubi0";
	log_level = 4;

	while ((c = getopt_long(argc, argv, opt_string, options, &i)) != -1) {
		switch(c) {
		case 'd':
			ubi_dev = optarg;
			break;
		case 'h':
			usage(argv[0]);
			break;
		case 'f':
			stats_file = optarg;
			break;
		case 'r':
			read_completion = atoi(optarg);
			break;
		case 's':
			scrub_completion = atoi(optarg);
			break;
		case 'x':
			read_threshold = atoi(optarg);
			break;
		case 'v':
			log_level = atoi(optarg);
			if (log_level < 0)
				log_level = 0;
			else if (log_level > 4)
				log_level = 4;
		case '?':
		default:
			break;

		}
	}
	/* signal handling */
	struct signalfd_siginfo fdsi;
	int sigfd = init_sigfd();
	if (sigfd < 0) {
		log_fatal("Could not init signal handling, aborting");
		_exit(EXIT_FAILURE);
	}

	/* init sched_list */
	peb_head = malloc(sizeof(struct peb_list));
	if (!peb_head) {
		log_fatal("Could not allocate peb_list");
		_exit(EXIT_FAILURE);
	}
	peb_head->peb = NULL;
	INIT_LIST_HEAD(&peb_head->list);
	sched_read_head = malloc(sizeof(struct sched_peb));
	if (!sched_read_head) {
		log_fatal("Could not allocate read scheduler");
		_exit(EXIT_FAILURE);
	}
	INIT_LIST_HEAD(&sched_read_head->list);
	sched_read_head->peb = NULL;
	sched_scrub_head = malloc(sizeof(struct sched_peb));
	if (!sched_read_head) {
		log_fatal("Could not allocate scrub scheduler");
		_exit(EXIT_FAILURE);
	}
	INIT_LIST_HEAD(&sched_scrub_head->list);
	sched_scrub_head->peb = NULL;
	int fd = open(ubi_dev, O_RDONLY);
	if (fd < 0) {
		log_fatal("Could not open device %s", ubi_dev);
		return 1;
	}

	/* get peb info */
	num_pebs = get_num_pebs(ubi_dev);
	if (num_pebs < 1) {
		log_err("Invalid number of PEBs");
		return 1;
	}
	if (init_stats(fd, &peb_head->list, num_pebs) < 0) {
		log_fatal("Could not init statistics, aborting");
		_exit(EXIT_FAILURE);
	}
	/* init peb list */
	log_debug("Number of PEBs: %" PRIu64, num_pebs);


	if (read_stats_file(stats_file, peb_head, sched_read_head, sched_scrub_head) < 0) {
		log_warn("Could not init stats from file %s", stats_file);
		/* init read and scrub lists */
		struct peb_list *p = NULL;
		list_for_each_entry(p, &peb_head->list, list) {
			schedule_peb(&sched_read_head->list, p->peb, SCHED_READ);
			schedule_peb(&sched_scrub_head->list, p->peb, SCHED_SCRUB);
		}
	}

	int shutdown = 0;
	int stats_timer = create_and_arm_timer(60);
	if (stats_timer < 0) {
		log_fatal("Could not create stats timer, aborting");
		_exit(1);
	}
	int read_peb_timer = create_and_arm_timer(read_completion / num_pebs);
	if (read_peb_timer < 0) {
		log_fatal("Could not create read timer, aborting");
		_exit(1);
	}
	int scrub_peb_timer = create_and_arm_timer(scrub_completion / num_pebs);
	if (scrub_peb_timer < 0) {
		log_fatal("Could not create scrubbing timer, aborting");
		_exit(1);
	}
	struct pollfd pfd[4];
	pfd[0].fd = sigfd;
	pfd[0].events = POLLIN;
	pfd[1].fd = stats_timer;
	pfd[1].events = POLLIN;
	pfd[2].fd = read_peb_timer;
	pfd[2].events = POLLIN;
	pfd[3].fd = scrub_peb_timer;
	pfd[3].events = POLLIN;
	while (!shutdown) {
		int n = poll(pfd, ARRAY_SIZE(pfd), -1);
		if (n == -1) {
			log_err("poll error: %s", strerror(errno));
			shutdown = 1;
		}
		if (n == 0) {
			continue;
		}
		/* signalfd */
		if (pfd[0].revents & POLLIN) {
			ssize_t s = read(sigfd, &fdsi, sizeof(fdsi));
			if (s != sizeof(fdsi)) {
				log_warn("Could not read from signal fd");
				continue;
			}
			switch(fdsi.ssi_signo) {
			case SIGUSR1:
				/* write back stats to disk */
				write_stats_file(stats_file, peb_head, sched_read_head, sched_scrub_head, num_pebs);
				break;
			default:
				shutdown = 1;
				break;
			}
		}
		/* stats timer */
		if (pfd[1].revents & POLLIN) {
			uint64_t tmp;
			read(stats_timer, &tmp, sizeof(tmp));
			/* update stats */
			if (update_stats(fd, peb_head, num_pebs) < 0) {
				log_warn("Could not update stats");
				continue;
			}

			struct peb_list *p = NULL;
			/* check if we need to act on any block */
			list_for_each_entry(p, &peb_head->list, list) {
				struct peb_info *peb = p->peb;
				if (!peb)
					continue;
				uint64_t read_stats = peb->read_cnt - peb->prev_read_cnt;
				/* read whole PEB if number of reads since last check is above threshold */
				if (read_stats >= read_threshold) {
					log_info("Too many reads for PEB %" PRIu64 " between stats updates, scheduling READ", peb->peb_num);
					read_peb(fd, peb);
				}
			}
		}

		/* read_peb_timer */
		if (pfd[2].revents & POLLIN) {
			uint64_t tmp;
			read(pfd[2].fd, &tmp, sizeof(tmp));
			/* do next peb read */
			if (work(sched_read_head, fd) < 0) {
				log_err("Error while reading PEB");
			}
		}

		/* scrub pebs */
		if (pfd[3].revents & POLLIN) {
			uint64_t tmp;
			read(pfd[3].fd, &tmp, sizeof(tmp));
			/* do next peb scrub */
			if (work(sched_scrub_head, fd) < 0) {
				log_err("Error while scrubbing PEB");
			}
		}

	}
	log_info("Shutting down");
	write_stats_file(stats_file, peb_head, sched_read_head, sched_scrub_head, num_pebs);
	close(fd);
	free_list(peb_head);

	return 0;
}
