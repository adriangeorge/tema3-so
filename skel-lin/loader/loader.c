/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include "exec_parser.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <fcntl.h>

static so_exec_t *exec;
static struct sigaction sa, old_sa;

typedef struct page_data {
	char wasMapped;
	int index;
	int page_len;
	char zeroFill;
} page_data;

typedef struct common_data {
	int global_page_count;
	int fd;
} common_data;

typedef struct segment_data {
	int page_count;
	page_data *pages;
	common_data *cdata;
} segment_data;

// Returns a reference to segment containing addr
// If no such segment is found return NULL
so_seg_t *find_segment(uintptr_t addr)
{
	// printf("Looking in %d segments\n", exec->segments_no);
	for (int i = 0; i < exec->segments_no; i++) {
		so_seg_t s = exec->segments[i];
		// printf("[%p %p]\n", s.vaddr,  s.vaddr + s.mem_size);
		if (addr >= s.vaddr && addr <= s.vaddr + s.mem_size) {
			return exec->segments + i;
		}
	}

	return NULL;
}

int was_mapped(page_data p) { return p.wasMapped; }

void sigsegv_handler(int sig, siginfo_t *info, void *ucontext)
{

	// Get fault address and find segment
	uintptr_t fault_addr = (uintptr_t)info->si_addr;
	so_seg_t *seg = find_segment(fault_addr);
	segment_data *sdata = (segment_data *)seg->data;
	int err = 0;

	// If fault address doesn't belong to any known segments
	// process SIGSEGV with default handler
	if (seg == NULL) {
		old_sa.sa_sigaction(sig, info, ucontext);
	}

	int sys_psize = getpagesize();
	int p_index = (fault_addr - seg->vaddr) / sys_psize;
	page_data *pdata = &sdata->pages[p_index];
	// Check if page has been mapped before
	// If page was mapped before process SIGSEGV with default handler
	if (was_mapped(*pdata)) {
		// printf("Page already mapped\n");
		old_sa.sa_sigaction(sig, info, ucontext);
	}
	pdata->wasMapped = 1;
	// If program reached this point mapping for page is needed
	uintptr_t *map_addr = (uintptr_t *)(seg->vaddr + p_index * sys_psize);
	void *ret = mmap(map_addr, sys_psize, PROT_WRITE | PROT_READ,
			 MAP_FIXED | MAP_ANON | MAP_PRIVATE, 0, 0);

	if ((int)ret == -1)
		exit(-1);

	memset(ret, 0, sys_psize);

	// Copy data from executable file

	if (pdata->page_len != 0) {
		char *buffer = calloc(sys_psize, sizeof(char));
		// Go to correct position in file
		err = lseek(sdata->cdata->fd, seg->offset + p_index * sys_psize,
			    SEEK_SET);
		if (err < 0) {
			perror("lseek");
			exit(-1);
		}
		err = read(sdata->cdata->fd, buffer, pdata->page_len);
		if (err < 0) {
			perror("lseek");
			exit(-1);
		}
		memcpy(ret, buffer, pdata->page_len);
	}
	err = mprotect(ret, sys_psize, seg->perm);
	if (err < 0) {
		perror("lseek");
		exit(-1);
	}
}

int so_init_loader(void)
{
	int err = 0;
	// Set up for sigaction structure
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = sigsegv_handler;

	// Intercept each SIGSEGV signal
	err = sigaction(SIGSEGV, &sa, &old_sa);
	if (err < 0) {
		perror("lseek");
		exit(-1);
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);

	int sys_psize = getpagesize();

	// Allocate memory for common data (used by all segments)
	common_data *cdata = calloc(1, sizeof(common_data));

	cdata->fd = open(path, O_RDONLY);
    if (cdata->fd < 0) {
        printf("Tried opening %s :", path);
		perror("lseek");
		exit(-1);
	}
	// Init segments additional data
	for (int i = 0; i < exec->segments_no; i++) {
		so_seg_t *s = &exec->segments[i];

		// Allocate memory for addditional data structures
		segment_data *seg_data = calloc(1, sizeof(segment_data));

		// If page's memsize not a multiple of system page size, add one
		// more page
		seg_data->page_count =
		    s->mem_size / sys_psize + (s->mem_size % sys_psize ? 1 : 0);
		// Store information for each page contained in segment, using
		// calloc will set mapped flag to desired value of false by
		// default
		seg_data->pages =
		    calloc(seg_data->page_count, sizeof(page_data));

		// Compute length for each page
		int full_pages = s->file_size / sys_psize;

		for (int j = 0; j < seg_data->page_count; j++) {
			if (j < full_pages) {
				seg_data->pages[j].page_len = sys_psize;
			} else if (j == full_pages) {
				seg_data->pages[j].page_len =
				    s->file_size % sys_psize;
			}
		}

		seg_data->cdata = cdata;
		s->data = seg_data;
	}

	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}
