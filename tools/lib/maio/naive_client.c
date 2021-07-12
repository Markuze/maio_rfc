#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX (16<<12)
#define PORT 5558
#define SA struct sockaddr

char buff[MAX];

void func(int sockfd)
{
        int n;

        for (;;) {
                write(sockfd, buff, sizeof(buff));
        }
}

int main()
{
        int sockfd, connfd;
        struct sockaddr_in servaddr, cli;

        // socket create and varification
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
                printf("socket creation failed...\n");
                exit(0);
        }
        else
                printf("Socket successfully created..\n");
        bzero(&servaddr, sizeof(servaddr));

        // assign IP, PORT
        servaddr.sin_family = AF_INET;
        //servaddr.sin_addr.s_addr = inet_addr("10.128.0.3");
        servaddr.sin_addr.s_addr = inet_addr("10.5.3.4");
        servaddr.sin_port = htons(PORT);

        // connect the client socket to server socket
        if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
                printf("connection with the server failed...\n");
                exit(0);
        }
        else
                printf("connected to the server..\n");

        // function for chat
        func(sockfd);

        // close the socket
        close(sockfd);
}
