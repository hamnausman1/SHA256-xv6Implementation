#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"


int main(void)
{


int start = gettime()/10000;
printf("time start:%d\n",start);
sha256();
int end = gettime()/10000;
printf("\n");
printf("time end:%d\n",end);
printf("total time taken in milliseconds: %d\n",end-start);


return 0;     
}
