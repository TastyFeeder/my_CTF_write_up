#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main()
{
    char result;
    char flag[25];
    flag[0] = 'a';
    flag[1] = 'i';
    flag[2] = 's';
    flag[3] = '3';
    int *ptr;
    ptr = (int*)flag;
//    int key = result[0] ^ ptr[0];
//    unsigned int t =1499400561;
    int count = 86400;
    while(count >0){
    
    srand(1499400561);
    for (int i = 0 ; i< 4;i++){
        flag[i] = rand() ^ flag[i]; 
    }
    flag[4] = '\0';
    printf("%d  %d\n",*flag,flag[1]);
}
/*
    while(1){
        srand(t);
        if(key == rand()){
            printf("here is the shit : %d",t);
            break;
        }
        t++;
        printf("%d\n",t);
        if(t == 0)break;
    }
*/
/*  
    int i ;
    for(i = 0, ptr = (int*)flag ; i < 7 ; ++i)
        ptr[i] = rand() ^ result[i];
    flag[28] = '\0';
    printf("%s\n",flag);
*/
    return 0;
}    
