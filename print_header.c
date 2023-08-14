#include <stdio.h>
#include <sys/socket.h>

int main(void) {
  struct msghdr msg = { 0 };
  size_t size = CMSG_SPACE(sizeof(char));

  printf("\n======= %zu", size);


  return 0;
}
