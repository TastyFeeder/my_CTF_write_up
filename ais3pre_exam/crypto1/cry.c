#include <stdio.h>

int main()
{
    int result[] ={964600246,1376627084,1208859320,1482862807,1326295511,1181531558,2003814564};
    char flag[29];
    flag[0] = 'A';
    flag[1] = 'I';
    flag[2] = 'S';
    flag[3] = '3';
    int *ptr;
    ptr = (int*)flag;
    int key = result[0] ^ ptr[0];
    int i ;
    for(i = 1, ptr = (int*)flag ; i < 7 ; ++i)
        ptr[i] = key ^ result[i];
    flag[28] = '\0';
    printf("%s\n",flag);
    return;
}    
