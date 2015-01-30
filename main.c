#include <stdio.h>
#include <string.h>



 void crypt(const char* originalMessage, char* codedMessage, char key) {
    unsigned int size = strlen(originalMessage);
    unsigned int i = 0;
    for(i=0; i<size; i++){
        codedMessage[i] = originalMessage[i];
        codedMessage[i] ^= key;
    }
    codedMessage[i] = '\n';
 }

int main(int argc, char** argv)
{
    unsigned int i = 0;
    char one[12]   = "8.4,425#-.25";
    char two[12]   = "?>!\\%#(0608?";
    char three[12] = ",\" LWQRWV''%";
    char four[12]  = "4!8\\2708=KVY";
    char keys[8] = {'c', 's', 'q', 'r', 'a', 'f', 'o', 'h'};
    char flag[13];


    for(i=0; i<9; i++){
        crypt(three, flag, keys[i]);
        if(strncmp(flag, "MCA", 3) == 0){
            printf("Your flag: %s", flag);
        }
    }
}

