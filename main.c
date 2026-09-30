#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>

#include <linux/netlink.h>
#include <linux/genetlink.h>

#define NLA_DATA(nla) \
    ((void *)((char *)(nla) + NLA_HDRLEN))

#define NLA_NEXT(nla, remaining) \
    ((remaining) -= NLA_ALIGN((nla)->nla_len), \
     (struct nlattr *)((char *)(nla) + \
                       NLA_ALIGN((nla)->nla_len)))

#define NLA_OK(nla, remaining) \
    ((remaining) >= (int)sizeof(struct nlattr) && \
     (nla)->nla_len >= sizeof(struct nlattr) && \
     (nla)->nla_len <= (remaining))

// size in bytes 
#define BUFFER_SIZE 4096

static char buffer[BUFFER_SIZE];


//helper to add attribute header to the Generik Netlink message
static int add_attribute(struct nlmsghdr *nlh, int maxlen, uint16_t type, const void* data, uint16_t data_len){

	struct nlattr *attr;

	// Attribute header + Attribute data
	int attr_len = NLA_HDRLEN + data_len;
	// alignment or padding
	int total_len = NLA_ALIGN(attr_len);

	if(NLMSG_ALIGN(nlh->nlmsg_len) + total_len > maxlen)
		return -1;

	attr = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));

	attr->nla_type = type;
	attr->nla_len = attr_len;

	memcpy((char *)attr + NLA_HDRLEN,data,data_len);

	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + total_len;

	return 0;
}

static int send_req_fwctl_kernel(int sock_fd, const char *family_name)
{
	//   Netlink message container
	// ----------------------------
	// |    Netlink header        |
	// |   struct nlmsghdr        |
	// |     nlmsg_len            |
	// |     nlmsg_type           |
	// |     nlmsg_flags          |
	// |__________________________|
	// |                          |
	// |  Generic Netlink header  |
	// |   struct genlmsghdr      |
	// |  cmd=CTRL_CMD_GETFFAMILY |
	// |   version = 1            |
	// |__________________________|
	// |                          |
	// |    Attribute header      |
	// |     struct nlattr        |
	// |type=CTRL_ATTR_FAMILY_NAME|
	// |     length = ...         |
	// |__________________________|
	// |                          |
	// |   Attribute data         |
	// |     "FWCTL"              |
	// ----------------------------

	memset(buffer, 0, sizeof(buffer));

	// the beginning of the Netlink message --> Netlink header.
	struct nlmsghdr *nlh =
		(struct nlmsghdr *)buffer;

	// Netlink header
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 1;
	nlh->nlmsg_pid = 0;

	// Generic Netlink header
	struct genlmsghdr *genlh;

	// the memory adress where Generic header starts
	genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);

	genlh->cmd = CTRL_CMD_GETFAMILY;
	genlh->version = 1;

	// Attribute header
	if (add_attribute(nlh,
		      sizeof(buffer),
		      CTRL_ATTR_FAMILY_NAME,
		      family_name,
		      strlen(family_name) + 1) < 0) {

		fprintf(stderr, "Failed to add attribute\n");
		return -1;
	}

	// Destination
	struct sockaddr_nl kernel;
	memset(&kernel, 0, sizeof(kernel));
	kernel.nl_family = AF_NETLINK;

	// memory buffer
	struct iovec iov = {
		.iov_base = nlh,
		.iov_len = nlh->nlmsg_len
	};

	// description of the entire message
	struct msghdr msg = {
		.msg_name = &kernel,
		.msg_namelen = sizeof(kernel),
		.msg_iov = &iov,
		.msg_iovlen = 1
	};

	// send request
	if (sendmsg(sock_fd, &msg, 0) < 0) {
		perror("sendmsg");
		return -1;
	}

	printf("GETFAMILY request sent\n");

	return 0;
}

static ssize_t recv_reply_kernel_fwctl(int sock_fd)
{
	memset(buffer, 0, sizeof(buffer));

	// Destination
	struct sockaddr_nl kernel;
	memset(&kernel, 0, sizeof(kernel));

	// memory buffer
	struct iovec iov = {
		.iov_base = buffer,
		.iov_len = sizeof(buffer)
	};

	// description of the entire message
	struct msghdr msg = {
		.msg_name = &kernel,
		.msg_namelen = sizeof(kernel),
		.msg_iov = &iov,
		.msg_iovlen = 1
	};

	// receive reply
	ssize_t len = recvmsg(sock_fd, &msg, 0);
	if (len < 0) {
		perror("recvmsg");
		return -1;
	}

	printf("Received %zd bytes\n",len);

	return len;
}

static int resolve_family_ID(ssize_t len)
{
	struct nlmsghdr *nlh =
		(struct nlmsghdr *)buffer;

	if(!NLMSG_OK(nlh,len)){
		fprintf(stderr,"Invalid Netlink Message\n");
		return -1;
	}

	struct genlmsghdr *genlh;
	genlh = (struct genlmsghdr *)NLMSG_DATA(nlh);

	int remaining =
	    nlh->nlmsg_len -
	    NLMSG_LENGTH(sizeof(struct genlmsghdr));

	struct nlattr *attr;

	for (attr = (struct nlattr *)((char *)genlh+GENL_HDRLEN);
	     NLA_OK(attr, remaining);
	     attr = NLA_NEXT(attr, remaining)) {

	    if (attr->nla_type == CTRL_ATTR_FAMILY_ID) {

		uint16_t family_id =
		    *(uint16_t *)NLA_DATA(attr);

		printf("FWCTL family ID = %u\n",
		       family_id);

		return family_id;
	    }
	}

	return -1;
}


int main(int argc,char **argv){

        /*for(int i=0;i<argc;i++){
		printf("%s ",argv[i]);		
		printf("%s ",*argv);
		argv++;
	}

	printf("\n ");*/

	if(argc < 2){
		printf("Not enough input arguments.\n");
		return 1;
	}

	int sock_fd;
	struct sockaddr_nl local;
	struct nlattr *attr;

	// create a Netlink socket
	sock_fd = socket(AF_NETLINK,SOCK_RAW,NETLINK_GENERIC);

	if(sock_fd < 0){
		perror("socket");
		return EXIT_FAILURE;
	}

	memset(&local,0,sizeof(local));

	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = 0;

	// bind a Netlink address to the socket
	if(bind(sock_fd,(struct sockaddr *)&local,sizeof(local)) < 0){
		perror("bind");
		close(sock_fd);
		return EXIT_FAILURE;
	}

	printf("Netlink socket %d is created.\n",sock_fd);


	/*** Netlink communication is bidirectional ***/
	//   fwctl <--> kernel
	//   ask for the family ID of the Netlink family name 'FWCTL'

	// send request 
	// fwctl --> kernel --> Generic Netlink Controller
	send_req_fwctl_kernel(sock_fd, "FWCTL");

	// receive reply 
	// kernel --> fwctl
	ssize_t len = recv_reply_kernel_fwctl(sock_fd);

	// extract the family ID from the Netlink reply 
	uint16_t family_id = resolve_family_ID(len);


	if(!strcmp(argv[1],"add")){
	}

	if(!strcmp(argv[1],"delete")){
	}

	if(!strcmp(argv[1],"update")){
	}

	close(sock_fd);

	return 0;
}


