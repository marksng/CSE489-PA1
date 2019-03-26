/**
 * @markng_assignment1
 * @author  Mark Ng <markng@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * This contains the main function. Add further description here....
 */
#include <stdio.h>
#include <stdlib.h>

#include "../include/global.h"
#include "../include/logger.h"

// additional includes
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h> 

#define MAXDATASIZE 500
#define CMDSIZE 50
#define BACKLOG 5
#define STDIN 0
struct user {
	char hostname[35]; 
	char ip_addr[16]; 
	int port; 
	int status; // -1=disconnected, 0=logged-out, 1=logged-in,
	int socket; 
	
	int msg_sent; 
	int msg_recv; 
	
	char buffered[100][MAXDATASIZE]; 
	int buff_size;  
	
	int num_blocked; 
	struct user *blocked[4]; // array of IPs that are blocked by the current user
	
	struct user *list_storage[4]; // list of LOCAL user storage for EXCEPTIONS (send, BLOCK, UNBLOCK
	int num_users; 
};

// more helpers, different kind of help 
/*
trim function borrowed from https://codeforwin.org/2016/04/c-program-to-trim-trailing-dsadasdasdasdasdasdasdasdadsadasdwhite-space-characters-in-string.html
*/
void trim(char * str) {
	
    int index, i;
    index = -1;
    i = 0;
    while(str[i] != '\0') {
        if(str[i] != ' ' && str[i] != '\t' && str[i] != '\n') {
            index= i;
        }
        i++;
    }
    str[index + 1] = '\0';
}
int is_port(char *s) { 
	for (int i = 0; i < strlen(s); ++i) { 
		if ((s[i] < '0' || s[i] > '9') && s[i] > -1) { 
			return 0; 
		}
	}
	return 1; 
}
int is_ip(char *ip) { 	
	char temp[16]; 
	memset(temp, '\0', 16);
	strcpy(temp, ip); 
	
	int num_args = 0; 
	char *args[20]; 
	
	args[num_args] = strtok(temp, "."); 
	while (args[num_args] != NULL) { 
		args[++num_args] = strtok(NULL, "."); 
	}
	
	if (num_args != 4) { 
		return 0; 
	}
	else { 
		for (int i = 0; i < num_args; ++i) { 
			for (int j = 0; j < strlen(args[i]); ++j) { 
				if (args[i][j] < '0' || args[i][j] > '9') {					
					return 0;
				}
			}
			int check = atoi(args[i]); 
			if (check > 256 || check < 0) { 			
				return 0;
			}
		}
	}
	return 1;
}
void sort_by_port(struct user *list, int num_users) { 
	for (int i = 0; i < num_users; ++i) { 
		int min = i; 
		for (int j = i+1; j < num_users; ++j) { 
			if (list[j].port < list[min].port) { 
				min = j; 
			}
		}
		struct user temp = list[i];
		list[i] = list[min]; 
		list[min] = temp; 
	}
}
void list_func(struct user* users, int size, char **list_format) { 
	// sort items by port
	sort_by_port(users, size); 
	int cnt = 1; 
	for (int i = 0; i < size; ++i) {
		if (users[i].status == 1) {		// users logged in
			char *buffer = (char*) malloc(sizeof(char)*MAXDATASIZE);
			memset(buffer, '\0', MAXDATASIZE);
			sprintf(buffer, "%-5d%-35s%-20s%-8d\n", cnt, users[i].hostname, users[i].ip_addr, users[i].port); 
			list_format[cnt-1] = buffer; 
			++cnt; 
		}
	}
}
int find_by_ip(char *ip, struct user users[], int num_users) { 
	for (int i = 0; i < num_users; ++i) { 
		if (strcmp(users[i].ip_addr, ip) == 0) { 
			return i; 
		}
	}
	return -1; // not found
}
int find_by_socket(int socket, struct user users[], int num_users) { 
	for (int i = 0; i < num_users; ++i) { 
		if (socket == users[i].socket) { 
			return i; 
		} 
	}
	return -1; 
}
int connect_to_host(char *server_ip, char *server_port_char, int host_port) {
	if (!is_ip(server_ip) || !is_port(server_port_char)) { 
		cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
		cse4589_print_and_log("[%s:END]\n", "LOGIN");
		return -1;
	}
	else { 
		int server_port = atoi(server_port_char); 
		int socketfd; 
		struct sockaddr_in server_addr, client_addr;

		socketfd = socket(AF_INET, SOCK_STREAM, 0); 
		if (socketfd < 0) { 
			perror("socket() failed\n"); 
		}
		bzero(&client_addr, sizeof(client_addr)); 
		client_addr.sin_family = AF_INET;
		client_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
		client_addr.sin_port = htons(host_port); 
		if (bind(socketfd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in)) != 0) { 
			perror("failed to bind port to client"); 
		}
		
		bzero(&server_addr, sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
		server_addr.sin_port = htons(server_port);

		if(connect(socketfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
			socketfd = -1; 
			cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
			cse4589_print_and_log("[%s:END]\n", "LOGIN");
			return -1; 
		}
		return socketfd;
	}
    
}
int start_server(int port) { 
	int server_socket = socket(AF_INET, SOCK_STREAM, 0); // return value
	struct sockaddr_in server_addr;
	// socket()
	server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket < 0) { 
		perror("socket() problemo"); exit(-1); 
	}
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
	server_addr.sin_port = htons(port); 
	// bind()
	if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) { 
		perror("bind() problemo"); exit(-1); 
	}
	// listen() 
	if (listen(server_socket, BACKLOG) < 0) { 
		perror("listen() problemo"); exit(-1); 
	}
	return server_socket; 
}
int ip_in_local(char *ip_addr, struct user *list_storage[], int num_users) { 
	for (int i = 0; i < num_users; ++i) {  
		if (strcmp((list_storage[i])->ip_addr, ip_addr) == 0) { 
			return i; 
		}
	} 
	return -1; 
}
int blocked_by(char *blocker, char *blockee, struct user users[], int num_users) { 
	int blocker_loc = find_by_ip(blocker, users, num_users); 	
	for (int i = 0; i < users[blocker_loc].num_blocked; ++i) {
		if (strcmp(users[blocker_loc].blocked[i]->ip_addr, blockee) == 0) { // blockee is blocked by blocker
			return 1; 
		}
	}
	return 0; 
}
// helper functions - 
void print_ip() { 
	char ip_addr[16]; 
	struct sockaddr_in addr; 
	int sockfd;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	addr.sin_family = AF_INET; 
	inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr); 
	addr.sin_port = htons(53); 
	if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { 
		cse4589_print_and_log("[%s:ERROR]\n", "IP");
		cse4589_print_and_log("[%s:END]\n", "IP");
		return; 
	}
	bzero(&addr, sizeof(addr));
	int len = sizeof(addr);
	getsockname(sockfd, (struct sockaddr *) &addr, &len);
	inet_ntop(AF_INET, &addr.sin_addr, ip_addr, sizeof(ip_addr));
	
	cse4589_print_and_log("[%s:SUCCESS]\n", "IP");
	cse4589_print_and_log("IP:%s\n", ip_addr);
	cse4589_print_and_log("[%s:END]\n", "IP");
	close(sockfd); 	
	return; 
}
void print_port(int port) {
	cse4589_print_and_log("[%s:SUCCESS]\n", "PORT");
	cse4589_print_and_log("PORT:%d\n", 	port);
	cse4589_print_and_log("[%s:END]\n", "PORT");	
	return; 
}
int send_helper(int from_socket, char *to_ip, char *buffer, struct user users[], int num_users) {
	int from_loc = find_by_socket(from_socket, users, num_users); 
	int to_loc = find_by_ip(to_ip, users, num_users); 
	char error[50] = "[SEND:ERROR]\n[SEND:END]\n"; 
	if (!is_ip(to_ip)) { // not a valid IP
		send(from_socket, error, strlen(error), 0);
		return 0; 
	}
	// checks local lists to see if the person trying to send to is logged in 
	int loc = ip_in_local(to_ip, users[from_loc].list_storage, users[from_loc].num_users);
	if (loc == -1) { 
		send(from_socket, error, strlen(error), 0);
		return 0; 
	}
	if (users[from_loc].list_storage[loc]->status != 1) { // user is not logged in on local list
		send(from_socket, error, strlen(error), 0);
		return 0; 
	}
	else { 
		int blocked = blocked_by(to_ip, users[from_loc].ip_addr, users, num_users); 
		char msg[MAXDATASIZE], to_client[MAXDATASIZE];	
		memset(msg, '\0', MAXDATASIZE); 
		memset(to_client, '\0', MAXDATASIZE); 
		int msg_len = (strlen(buffer) - (strlen("SEND") + strlen(to_ip) + 2));	// message prep
		int start = strlen("SEND") + 1 + strlen(to_ip) + 1; 
		memcpy(msg, buffer + start, msg_len); 
		msg[msg_len] = '\0'; 
		// this message sends to the client RECEIVING 
		sprintf(to_client, "[RECEIVED:SUCCESS]\nmsg from:%s\n[msg]:%s\n[RECEIVED:END]\n", users[from_loc].ip_addr, msg);
		if (!blocked) { 
			if (users[to_loc].status == 1) { // check server side to see if logged in 
				send(users[to_loc].socket, to_client, strlen(to_client), 0);
					
			}
			else {
				if (users[to_loc].status == 0) {
					strcpy(users[to_loc].buffered[users[to_loc].buff_size], to_client); 
					users[to_loc].buff_size++; 
					users[to_loc].msg_recv++;	
				}
			}
			users[to_loc].msg_recv++;	
		}
		users[from_loc].msg_sent++;
		char success[50] = "[SEND:SUCCESS]\n[SEND:END]\n";		
		send(from_socket, success, strlen(success), 0); 
		cse4589_print_and_log("[RELAYED:SUCCESS]\nmsg from:%s, to:%s\n[msg]:%s\n[RELAYED:END]\n", users[from_loc].ip_addr, to_ip, msg); 
	}
}
int broadcast_helper(int from_socket, char *buffer, struct user users[], int num_users) {
	int from_loc = find_by_socket(from_socket, users, num_users); 
	
	int msg_len = (strlen(buffer) - (strlen("BROADCAST") + 1));	// message prep
	int start = strlen("BROADCAST") + 1;
	char *msg = (char*) malloc(sizeof(char) * msg_len); 
	memcpy(msg, buffer + start, msg_len);
	msg[msg_len] = '\0'; 
	
	char to_clients[MAXDATASIZE]; 
	sprintf(to_clients, "[RECEIVED:SUCCESS]\nmsg from:%s\n[msg]:%s\n[RECEIVED:END]\n", users[from_loc].ip_addr, msg);
	for (int i = 0; i < num_users; ++i) { 
		int blocked = blocked_by(users[i].ip_addr, users[from_loc].ip_addr, users, num_users); 
		if (users[i].socket != from_socket && !blocked) { 
			if (users[i].status == 1) { 
				send(users[i].socket, to_clients, strlen(to_clients), 0);
			}
			else { 
				if (users[i].status == 0) {
					strcpy(users[i].buffered[users[i].buff_size], to_clients); 
					users[i].buff_size++; 
				}			
			}
			users[i].msg_recv++;
			users[from_loc].msg_sent++; 
		}		
	}
	char success[75] = "[BROADCAST:SUCCESS]\n[BROADCAST:END]\n";
	send(from_socket, success, strlen(success), 0); 
	cse4589_print_and_log("[RELAYED:SUCCESS]\nmsg from:%s, to:%s\n[msg]:%s\n[RELAYED:END]\n", users[from_loc].ip_addr, "255.255.255.255", msg); 
}
int block(int socket, char *ip, struct user users[], int num_users) { 
	int blocker = find_by_socket(socket, users, num_users); 
	int blockee = find_by_ip(ip, users, num_users); 
	char error[50] = "[BLOCK:ERROR]\n[BLOCK:END]\n";
	if (!is_ip(ip)) { // not valid IP
		send(socket, error, strlen(error), 0); 
		return 0;
	}
	if (ip_in_local(ip, users[blocker].list_storage, users[blocker].num_users) == -1) { // not in local
		send(socket, error, strlen(error), 0); 
		return 0;
	}
	if (blocked_by(users[blocker].ip_addr, ip, users, num_users)) { // already blocked
		send(socket, error, strlen(error), 0); 
		return 0; 
	}
	users[blocker].blocked[users[blocker].num_blocked] = &users[blockee]; 
	users[blocker].num_blocked++; 
	char success[50] = "[BLOCK:SUCCESS]\n[BLOCK:END]\n"; 
	send(socket, success, strlen(success), 0); 
	return 1; 	
}
int unblock(int socket, char *ip, struct user users[], int num_users) { 
	int unblocker = find_by_socket(socket, users, num_users); 
	char error[50] = "[UNBLOCK:ERROR]\n[UNBLOCK:END]\n";
	if (!is_ip(ip)) { 	// not valid IP
		send(socket, error, strlen(error), 0); 
		return 0; 
	}
	if (ip_in_local(ip, users[unblocker].list_storage, users[unblocker].num_users) == -1) { // not in local
		send(socket, error, strlen(error), 0); 
		return 0; 
	}
	int blocked = blocked_by(users[unblocker].ip_addr, ip, users, num_users) - 1; 
	if (blocked == -1) { // not blocked		
		send(socket, error, strlen(error), 0); 
		return 0; 
	}
	for (int i = blocked; i < users[unblocker].num_blocked; ++i) { 
		users[unblocker].blocked[i] = users[unblocker].blocked[i+1];
	}
	users[unblocker].num_blocked--; 
	char success[50] = "[UNBLOCK:SUCCESS]\n[UNBLOCK:END]\n"; 
	return 1; 
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void server_side(char* port_char) { 
	if (!is_port(port_char)) { 
		perror ("not a valid port!"); 
		return; 
	}
	int port = atoi(port_char); 
	int server_socket = start_server(port); 
// for select() 
	int head_socket, selret, sock_idx, fdaccept=0, caddr_len;
	struct sockaddr_in client_addr; 
	fd_set master_list, watch_list;
	// zero FD sets
	FD_ZERO(&master_list); 
	FD_ZERO(&watch_list); 
	// register listening socket & STDIN to mastear_list
	FD_SET(server_socket, &master_list); 
	FD_SET(STDIN, &master_list); 
	
	head_socket = server_socket; 
	
// application stuff 
	struct user users[4]; 
	int num_users = 0; 
	
	while(1) { 
		memcpy(&watch_list, &master_list, sizeof(master_list)); 
		// select() system call, it'll block? 
		if ((selret = select(head_socket + 1, &watch_list, NULL, NULL, NULL)) < 0) { 
			perror("select() problemo"); 
			exit(-1);
		} 
		else { // sockets available to process
			// loop through sockets to see which ones are ready 
			for (sock_idx = 0; sock_idx <= head_socket; ++sock_idx) { 
				if (FD_ISSET(sock_idx, &watch_list)) { 
					if (sock_idx == STDIN) { // get SERVER commands 
						char *input = (char*) malloc(sizeof(char)*MAXDATASIZE);
						memset(input, '\0', MAXDATASIZE);
						if(fgets(input, MAXDATASIZE-1, stdin) == NULL) { //Mind the newline character that will be written to msg
							exit(-1);
						}
					// changing string input to array of arguments	
						trim(input);						
						char *cmd = (char*) malloc(sizeof(char)*CMDSIZE);
						memset(cmd, '\0', CMDSIZE); 
						int num_args = 0; 
						char *args[100]; // maximum of 100 words allowed
						if (strcmp("", input) != 0) { 
							char *temp = (char*) malloc(sizeof(char)*strlen(input)); 
							strcpy(temp, input); 
							args[num_args] = strtok(temp, " "); 
							while (args[num_args] != NULL) { 
								args[++num_args] = strtok(NULL, " "); 
							}
							strcpy(cmd, args[0]); 
							trim(cmd); 
							if (num_args == 1) { 
								args[0][strlen(args[0])] = '\0';
							}
//							free(temp); 
						}
						if (strcmp(cmd, "AUTHOR") == 0) { 
							cse4589_print_and_log("[%s:SUCCESS]\n", cmd);
							cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "markng");
							cse4589_print_and_log("[%s:END]\n", cmd);
						}
						else if (strcmp(cmd, "IP") == 0) { print_ip(); }
						else if (strcmp(cmd, "PORT") == 0) { print_port(port); }
						else if (strcmp(cmd, "LIST") == 0) { 
							sort_by_port(users, num_users); 
							int x = 1;
							cse4589_print_and_log("[%s:SUCCESS]\n", cmd);
							for (int i = 0; i < num_users; ++i) { 
								if (users[i].status == 1) { 
									cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", x, users[i].hostname, users[i].ip_addr, users[i].port); 
									++x;
								}
							}
							cse4589_print_and_log("[%s:END]\n", cmd);
						}
						else if (strcmp(cmd, "STATISTICS") == 0) {
							// sort by port 
							sort_by_port(users, num_users);  
							// print out statistics
							cse4589_print_and_log("[%s:SUCCESS]\n", cmd);
							for (int i = 0; i < num_users; ++i) {
								if (users[i].status == 1 || users[i].status == 0) { 
									char *status; 
									if (users[i].status == 1) { 
										status = "logged-in"; 
									}
									else if (users[i].status == 0) { 
										status = "logged-out"; 
									}
									else { /* do nothing, unidentified status */ }
									cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", i+1, users[i].hostname, users[i].msg_sent, users[i].msg_recv, status);
								}
							} 
							cse4589_print_and_log("[%s:END]\n", cmd);
						}
						else if (strcmp(cmd, "BLOCKED") == 0) { 
							char success[50] = "[BLOCKED:SUCCESS]\n[BLOCKED:END]\n"; 
							char error[50] = "[BLOCKED:ERROR]\n[BLOCKED:END]\n"; 
							if (!is_ip(args[1]) || (find_by_ip(args[1], users, num_users) == -1)) { 
								cse4589_print_and_log(error); 
							}
							else { 
								int loc = find_by_ip(args[1], users, num_users);
								cse4589_print_and_log("[BLOCKED:SUCCESS]\n"); 
								for (int i = 0; i < users[loc].num_blocked; ++i) {
									cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", i, users[loc].blocked[i]->hostname, users[loc].blocked[i]->ip_addr, users[loc].blocked[i]->port); 									
								}
								cse4589_print_and_log("[BLOCKED:END]\n"); 
							}
							
						}
						else { /* no other input should need to be handled specifically */ }
					}
					else if (sock_idx == server_socket) { // handle new clients
						caddr_len = sizeof(client_addr); 
						if ((fdaccept = accept(server_socket, (struct sockaddr *)&client_addr, &caddr_len)) < 0) { 
							perror("accept() on incoming client failed");
						}
						else { // client logged in 						
							char ip_addr[16]; 
							inet_ntop(AF_INET, &client_addr.sin_addr, ip_addr, sizeof(ip_addr));
							int loc = find_by_ip(ip_addr, users, num_users); 
							int logged_in_before = 0; 
							if (loc > -1)  {
								logged_in_before = 1; 
							} 
							if (logged_in_before) { 
								users[loc].status = 1; // log user back in
								users[loc].socket = fdaccept; // update to current connected socket
							} 
							else { // has not logged in before or EXITed client
								struct user new_user;
								memset(new_user.hostname, '\0', 35); 
								if (strcmp(ip_addr, "128.205.36.33") == 0) { strcpy(new_user.hostname, "highgate.cse.buffalo.edu"); }
								else if (strcmp(ip_addr, "128.205.36.34") == 0) { strcpy(new_user.hostname, "euston.cse.buffalo.edu"); }
								else if (strcmp(ip_addr, "128.205.36.35") == 0) { strcpy(new_user.hostname, "embankment.cse.buffalo.edu"); }
								else if (strcmp(ip_addr, "128.205.36.46") == 0) { strcpy(new_user.hostname, "stones.cse.buffalo.edu"); }
								else if (strcmp(ip_addr, "128.205.36.36") == 0) { strcpy(new_user.hostname, "underground.cse.buffalo.edu");	}
								else { strcpy(new_user.hostname, "?????.cse.buffalo.edu"); }  // unidentified server							
								strcpy(new_user.ip_addr, ip_addr); 
								new_user.port = ntohs(client_addr.sin_port); 
								new_user.status = 1; 
								new_user.socket = fdaccept; 							
								new_user.msg_sent = 0; 						
								new_user.msg_recv = 0;
								new_user.buff_size = 0; 
								new_user.num_blocked = 0; 
								users[num_users] = new_user; 
								num_users++;
							}
							// add back into the list of sockets to watch
							FD_SET(fdaccept, &master_list); 
							if (fdaccept > head_socket) { 
								head_socket = fdaccept; 
							}
							// save current LIST in storage for future SEND, BLOCK, UNBLOCK comands
							loc = find_by_ip(ip_addr, users, num_users); 
							for (int i = 0; i < num_users; ++i) { 
								users[loc].list_storage[i] = &users[i]; 
							}		
							users[loc].num_users = num_users; 
							// sends the user the current list - 
							char *temp[num_users];
							list_func(users, num_users, temp); 
							char *sendable = (char*) malloc(sizeof(char) * MAXDATASIZE); 
							memset(sendable, '\0', MAXDATASIZE); 
							for (int i = 0; i < num_users; ++i) { 
								strcat(sendable, temp[i]); 
							}
							send (fdaccept, sendable, strlen(sendable), 0);
							// sends the first section of LOGIN response messages
							char success[50] = "[LOGIN:SUCCESS]\n";
							send (fdaccept, success, strlen(success), 0); 
							// sends the user the buffered messages - 
							if (logged_in_before) { 
								for (int i = 0; i < users[loc].buff_size; ++i) { 
									send(fdaccept, users[loc].buffered[i], strlen(users[loc].buffered[i]), 0);						
								}
								users[loc].buff_size = 0; 
							}
							// sends second half of LOGIN response message
							char end[50] = "[LOGIN:END]\n"; 
							send(fdaccept, end, strlen(end), 0);
						}
					}
					else { // handle current clients' inputs
						char *buffer = (char*) malloc(sizeof(char)*MAXDATASIZE);
						memset(buffer, '\0', MAXDATASIZE);
						if (recv(sock_idx, buffer, MAXDATASIZE, 0) <= 0) {	// client disconnected
							int remove = find_by_socket(sock_idx, users, num_users); 
							if (remove != -1) { 
								for (int i = remove; i < num_users; ++i) {
									users[i] = users[i+1];
								}
								num_users--; 
								close(sock_idx); 
								FD_CLR(sock_idx, &master_list); 
							}
						}
						else { 
							// convert string to args and set cmd 
							trim(buffer); 
							char *temp = (char*) malloc(sizeof(char)*strlen(buffer)); 
							strcpy(temp, buffer); 
							
							char *args[100]; // maximum of 100 words allowed
							int num_args = 0; 
							args[num_args] = strtok(temp, " "); 
							while (args[num_args] != NULL) { 
								args[++num_args] = strtok(NULL, " "); 
							}
							char *cmd = (char*) malloc(sizeof(char)*CMDSIZE);
							memset(cmd, '\0', CMDSIZE); strcpy(cmd, args[0]); 
							trim(cmd); 
							// process client commands
							if (strcmp("LOGOUT", cmd) == 0) {
								int loc = find_by_socket(sock_idx, users, num_users); 
								users[loc].status = 0; 
								close(sock_idx); 
								FD_CLR(sock_idx, &master_list);
							}
							else if (strcmp("EXIT", cmd) == 0) {
								int loc = find_by_socket(sock_idx, users, num_users); 
								for (int i = loc; i < num_users; ++i) {
									users[i] = users[i+1]; 
								}
								num_users--; 
								close(sock_idx); 
								FD_CLR(sock_idx, &master_list);	
							}
							else if (strcmp("REFRESH", cmd) == 0) {
								// fetch list, place into a buffer
								char *temp[num_users];
								list_func(users, num_users, temp); 
								char *list = (char*) malloc(sizeof(char) * MAXDATASIZE); 
								memset(list, '\0', strlen(list)); 
								for (int i = 0; i < num_users; ++i) { 
									strcat(list, temp[i]); 
								}
								// send out
								send(sock_idx, list, strlen(list), 0); 
								// save list in user files
								int loc = find_by_socket(sock_idx, users, num_users);
								for (int i = 0; i < num_users; ++i) { 
									users[loc].list_storage[i] = &users[i]; 
								} 
								users[loc].num_users = num_users; 
								char success[50] = "[REFRESH:SUCCESS]\n[REFRESH:END]\n"; 
								send(sock_idx, success, strlen(success), 0); 
							}
							else if (strcmp("SEND", cmd) == 0) {
								send_helper(sock_idx, args[1], buffer, users, num_users); 
							}
							else if (strcmp("BROADCAST", cmd) == 0) {
								broadcast_helper(sock_idx, buffer, users, num_users);
							}
							else if (strcmp("BLOCK", cmd) == 0) {
								block(sock_idx, args[1], users, num_users); 
							}
							else if (strcmp("UNBLOCK", cmd) == 0) {
								unblock(sock_idx, args[1], users, num_users); 
							}
							else { /* do nothing, command not recognized or handled in client */ }
						}
					} 					
				}		
				
			}
		}	
	}		
}


void client_side(char* port_char) { 
	if (!is_port(port_char)) { 
		// error
		perror( "not valid port!"); 
		return; 
	}
	int port = atoi(port_char); 
	int server = -1;
	char *list_storage = (char*) malloc(sizeof(char)*1000); // string that holds LIST information. updated with REFRESH
	memset(list_storage, '\0', 1000); 
	int refresh = 0, login = 0; 
	int selret, sock_idx, head_socket; 
	fd_set watch_list, master_list;  
	// zero FD sets
	FD_ZERO(&master_list); 
	FD_ZERO(&watch_list); 
	// register STDIN to master_list
	FD_SET(STDIN, &master_list); 
	head_socket = STDIN; 
	
	while(1) { 		
		memcpy(&watch_list, &master_list, sizeof(master_list)); 
		// select() system call, it'll block? 
		if ((selret = select(head_socket + 1, &watch_list, NULL, NULL, NULL)) < 0) { 
			perror("select() problemo"); 
			exit(-1);
		} 
		else { // sockets available to process
			// loop through sockets to see which ones are ready 
			for (sock_idx = 0; sock_idx <= head_socket; ++sock_idx) { 
				if (FD_ISSET(sock_idx, &watch_list)) { 
					if (sock_idx == STDIN) { // get client input
						char *input = (char*) malloc(sizeof(char)*MAXDATASIZE);
						memset(input, '\0', MAXDATASIZE);
						if(fgets(input, MAXDATASIZE-1, stdin) == NULL) { //Mind the newline character that will be written to msg
							exit(-1);
						}
					// changing string input to array of arguments	
						trim(input);
						
						char *cmd = (char*) malloc(sizeof(char)*CMDSIZE);
						memset(cmd, '\0', CMDSIZE); 
						int num_args = 0; 
						char *args[100]; // maximum of 100 words allowed
						if (strcmp("", input) != 0) { 
							char *temp = (char*) malloc(sizeof(char)*strlen(input)); 
							strcpy(temp, input); 
							args[num_args] = strtok(temp, " "); 
							while (args[num_args] != NULL) { 
								args[++num_args] = strtok(NULL, " "); 
							}
							strcpy(cmd, args[0]); 
							trim(cmd); 
							if (num_args == 1) { 
								args[0][strlen(args[0])] = '\0';
							}
//							free(temp); 
						}						 
					// process commands	given by client	
						if (strcmp(cmd, "AUTHOR") == 0) { 
							cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "markng");
						}
						else if (strcmp(cmd, "IP") == 0) { print_ip(); }
						else if (strcmp(cmd, "PORT") == 0) { print_port(port); }
						else if (strcmp(cmd, "LOGIN") == 0) {
							if (num_args == 3) { 
								server = connect_to_host(args[1], args[2], port); 
								if (server > -1) { 
									FD_SET(server, &master_list); 
									if (server > head_socket) { 
										head_socket = server; 
									} 
									login = 1; 
								} 
								else { 
									cse4589_print_and_log("[%s:ERROR]\n", cmd);
									cse4589_print_and_log("[%s:END]\n", cmd);
								}
							}
						}
						else if (strcmp(cmd, "EXIT") == 0) {
							if (server == -8) { // previously logged out?? server should be set to -8
								server = connect_to_host(args[1], args[2], port); 
							}
							if (server > 0) { 
								send(server, cmd, strlen(cmd), 0); 
								// let server disconnect from client
							}
							cse4589_print_and_log("[%s:SUCCESS]\n", cmd);
							cse4589_print_and_log("[%s:END]\n", cmd);
							exit(0); 
						}
						else { // server handled commands
							if (server > 0) { 
								if (strcmp("LIST", cmd) == 0) {
									cse4589_print_and_log("[%s:SUCCESS]\n", cmd);
									cse4589_print_and_log("%s", list_storage); 
									cse4589_print_and_log("[%s:END]\n", cmd);
								}
								else { 
									send(server, input, strlen(input), 0); // communicate with server 
									if (strcmp("LOGOUT", cmd) == 0) {															
										FD_CLR(server, &master_list); 
										close(server); 
										server = -8; 
										cse4589_print_and_log("[%s:SUCCESS]\n", cmd);
										cse4589_print_and_log("[%s:END]\n", cmd);
									}
									else if (strcmp("REFRESH", cmd) == 0) { 
										refresh = 1; 
									}
									else { /* do nothing, everything else gets sent to the server */ }
								}		
							}
						}
					}
					else if (sock_idx == server) { 
						char *buffer = (char*) malloc(sizeof(char)*MAXDATASIZE);
						memset(buffer, '\0', MAXDATASIZE);
						if (recv(server, buffer, MAXDATASIZE, 0) <= 0) { 
							FD_CLR(sock_idx, &master_list); 
							close(server); 
						}
						else {
							if (!refresh && !login) { 
								cse4589_print_and_log("%s", buffer); 
								fflush(stdout); 
							}
							if (refresh || login) {
								strcpy(list_storage, buffer); 
								refresh = 0;
								login = 0; 
							}
						}
					}
					else { /* do nothing */ }
				}
			}
		}
	}
}


/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */
int main(int argc, char **argv)
{
	/*Init. Logger*/
	cse4589_init_log(argv[2]);

	/*Clear LOGFILE*/
	fclose(fopen(LOGFILE, "w"));

	/*Start Here*/
	if (argc == 3) { // program name, client/server, listening port
		// extract PORT
		// C(client)/S(server) separation
		if (strcmp("s", argv[1]) == 0) { // running as SERVER
			server_side(argv[2]); 
		}
		else if (strcmp("c", argv[1]) == 0) { // running as CLIENT
			client_side(argv[2]); 
		}
		else { perror("./[name of file] [c/s] [port]"); exit(-1); }	
	}
	else { perror("./[name of file] [c/s] [port]"); exit(-1); }

	return 0;
}



















