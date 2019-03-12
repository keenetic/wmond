/*
 *	Wireless Tools
 *
 *		Jean II - HPL 99->04
 *
 * Main code for "iwevent". This listent for wireless events on rtnetlink.
 * You need to link this code against "iwcommon.c" and "-lm".
 *
 * Part of this code is from Alexey Kuznetsov, part is from Casey Carter,
 * I've just put the pieces together...
 * By the way, if you know a way to remove the root restrictions, tell me
 * about it...
 *
 * This file is released under the GPL license.
 *     Copyright (c) 1997-2004 Jean Tourrilhes <jt@hpl.hp.com>
 */

/***************************** INCLUDES *****************************/

#include "iwlib.h"		/* Header */

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <time.h>
#include <poll.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <regex.h>

/* Ugly backward compatibility :-( */
#ifndef IFLA_WIRELESS
#define IFLA_WIRELESS	(IFLA_MASTER + 1)
#endif /* IFLA_WIRELESS */

#define ALIAS_MAX_COUNT	128
#define ALIAS_MAX_LENGTH	64

#define STRING_MAX_SIZE	128

#define IW_SYSLOG_EVENT_MIN			0x0200
#define IW_SYSLOG_EVENT_MAX			0x0600

#define	IW_ASSOC_EVENT_FLAG                         0x0200
#define	IW_DISASSOC_EVENT_FLAG                      0x0201
#define	IW_DEAUTH_EVENT_FLAG                        0x0202
#define	IW_AGEOUT_EVENT_FLAG                        0x0203

#define MAC_REGEXP "STA\\(([0-9a-f]{2})\\:([0-9a-f]{2})\\:([0-9a-f]{2})\\:([0-9a-f]{2})\\:([0-9a-f]{2})\\:([0-9a-f]{2})\\)"
#define CLEANUP_FB "/tmp/run/cleanupneigh.fb"

typedef struct iface_alias
{
	struct iface_alias *next;
	char ifname[IFNAMSIZ + 1];
	char *alias;
} iface_alias;

static struct iface_alias *_aliases = NULL;
static const char *_mapfile = NULL;
static int _reload_map = 0;

static void __skip_spaces(const char **p)
{
	while( isspace(**p) ) {
		(*p)++;
	}
}

static void __skip_nonspaces(const char **p)
{
	while( **p != '\0' && !isspace(**p) ) {
		(*p)++;
	}
}

static void _aliases_free()
{
	struct iface_alias *a = _aliases;

	while (a != NULL) {
		_aliases = a->next;
		free(a->alias);
		free(a);
		a = _aliases;
	}
}

static int _aliases_reload()
{
	FILE* fp = NULL;
	int reloaded = 1;
	unsigned long count = 0;
	char s[STRING_MAX_SIZE + 1];
	const char *p = NULL;
	const char *sstart = NULL;
	const char *send = NULL;
	const char *astart = NULL;
	const char *aend = NULL;
	struct iface_alias *a = NULL;
	size_t l = 0;

	_aliases_free();

	if (_mapfile != NULL) {
		fp = fopen(_mapfile, "r");

		if (fp == NULL) {
			reloaded = 1;
		} else {
			while (
				!ferror(fp) && !feof(fp) &&
				count <= ALIAS_MAX_COUNT &&
				fgets(s, sizeof(s) - 1, fp) != NULL &&
				reloaded )
			{
				/* Read string in the format "<system name> <alias>". */
				s[sizeof(s) - 1] = 0;
				l = strlen(s);

				/* If the newline character is presented
				 * it is always the last symbol; remove it. */

				if (s[l - 1] == '\n') {
					s[l - 1] = '\0';
				}

				p = s;
				__skip_spaces(&p);

				if (*p == '\0') {
					/* Skip an empty string. */
				} else {
					sstart = p;
					__skip_nonspaces(&p);
					send = p;
					__skip_spaces(&p);
					astart = p;
					__skip_nonspaces(&p);
					aend = p;
					__skip_spaces(&p);

					if (*p != '\0') {
						/* Trailing symbols in the string. */
						reloaded = 0;
					} else
					if (sstart == send || send - sstart > IFNAMSIZ ||
						astart == aend || aend - astart > ALIAS_MAX_LENGTH)
					{
						/* A system name or alias has an invalid length. */
						reloaded = 0;
					} else
					if ((a = calloc(1, sizeof(*a))) == NULL) {
						/* Not enough memory. */
						reloaded = 0;
					} else {
						/* strncat is possible here since all
						 * memory is calloc'ed. */

						strncat(a->ifname, sstart, send - sstart);
						a->alias = calloc(1, aend - astart + 1);

						if (a->alias == NULL) {
							/* Not enough memory. */
							reloaded = 0;
							free(a);
						} else {
							strncat(a->alias, astart, aend - astart);

							a->next = _aliases;
							_aliases = a;

							++count;
						}
					}
				}
			}

			reloaded = reloaded && !ferror(fp) && count <= ALIAS_MAX_COUNT;
			fclose(fp);
		}
	}

	if (!reloaded) {
		_aliases_free();
	}

	return reloaded;
}

static const char *_aliases_find(const char *ifname)
{
	struct iface_alias *a = _aliases;

	while (a != NULL && strcmp(a->ifname, ifname) != 0) {
		a = a->next;
	}

	return (a == NULL) ? ifname : a->alias;
}

static void _sighup(int signal)
{
	_reload_map = 1;
}

/****************************** TYPES ******************************/

/*
 * Static information about wireless interface.
 * We cache this info for performance reason.
 */
typedef struct wireless_iface
{
  /* Linked list */
  struct wireless_iface *	next;

  /* Interface identification */
  int		ifindex;		/* Interface index == black magic */

  /* Interface data */
  char			ifname[IFNAMSIZ + 1];	/* Interface name */
  struct iw_range	range;			/* Wireless static data */
  int			has_range;
} wireless_iface;

/**************************** VARIABLES ****************************/

/* Cache of wireless interfaces */
struct wireless_iface *	interface_cache = NULL;

/************************ RTNETLINK HELPERS ************************/
/*
 * The following code is extracted from :
 * ----------------------------------------------
 * libnetlink.c	RTnetlink service routines.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 * -----------------------------------------------
 */

struct rtnl_handle
{
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	__u32			seq;
	__u32			dump;
};

static inline void rtnl_close(struct rtnl_handle *rth)
{
	close(rth->fd);
}

static inline int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions)
{
	int addr_len;

	memset(rth, 0, sizeof(*rth));

	rth->fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rth->fd < 0) {
		perror("Cannot open netlink socket");
		return -1;
	}

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
		perror("Cannot bind netlink socket");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr*)&rth->local,
			(socklen_t *) &addr_len) < 0) {
		perror("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		fprintf(stderr, "Wrong address length %d\n", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		fprintf(stderr, "Wrong address family %d\n", rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);
	return 0;
}

/******************* WIRELESS INTERFACE DATABASE *******************/
/*
 * We keep a few information about each wireless interface on the
 * system. This avoid to query this info at each event, therefore
 * reducing overhead.
 *
 * Each interface is indexed by the 'ifindex'. As opposed to interface
 * names, 'ifindex' are never reused (even if you reactivate the same
 * hardware), so the data we cache will never apply to the wrong
 * interface.
 * Because of that, we are pretty lazy when it come to purging the
 * cache...
 */

/*------------------------------------------------------------------*/
/*
 * Get name of interface based on interface index...
 */
static inline int
index2name(int		skfd,
	   int		ifindex,
	   char *	name)
{
  struct ifreq	irq;
  int		ret = 0;

  memset(name, 0, IFNAMSIZ + 1);

  /* Get interface name */
  irq.ifr_ifindex = ifindex;
  if(ioctl(skfd, SIOCGIFNAME, &irq) < 0)
    ret = -1;
  else
    strncpy(name, irq.ifr_name, IFNAMSIZ);

  return(ret);
}

/*------------------------------------------------------------------*/
/*
 * Get interface data from cache or live interface
 */
static struct wireless_iface *
iw_get_interface_data(int	ifindex)
{
  struct wireless_iface *	curr;
  int				skfd = -1;	/* ioctl socket */

  /* Search for it in the database */
  curr = interface_cache;
  while(curr != NULL)
    {
      /* Match ? */
      if(curr->ifindex == ifindex)
	{
	  //printf("Cache : found %d-%s\n", curr->ifindex, curr->ifname);

	  /* Return */
	  return(curr);
	}
      /* Next entry */
      curr = curr->next;
    }

  /* Create a channel to the NET kernel. Doesn't happen too often, so
   * socket creation overhead is minimal... */
  if((skfd = iw_sockets_open()) < 0)
    {
      perror("iw_sockets_open");
      return(NULL);
    }

  /* Create new entry, zero, init */
  curr = calloc(1, sizeof(struct wireless_iface));
  if(!curr)
    {
      fprintf(stderr, "Malloc failed\n");
      return(NULL);
    }
  curr->ifindex = ifindex;

  /* Extract static data */
  if(index2name(skfd, ifindex, curr->ifname) < 0)
    {
      perror("index2name");
      free(curr);
      return(NULL);
    }
  curr->has_range = (iw_get_range_info(skfd, curr->ifname, &curr->range) >= 0);
  //printf("Cache : create %d-%s\n", curr->ifindex, curr->ifname);

  /* Done */
  iw_sockets_close(skfd);

  /* Link it */
  curr->next = interface_cache;
  interface_cache = curr;

  return(curr);
}

/*------------------------------------------------------------------*/
/*
 * Remove interface data from cache (if it exist)
 */
static void
iw_del_interface_data(int	ifindex)
{
  struct wireless_iface *	curr;
  struct wireless_iface *	prev = NULL;
  struct wireless_iface *	next;

  /* Go through the list, find the interface, kills it */
  curr = interface_cache;
  while(curr)
    {
      next = curr->next;

      /* Got a match ? */
      if(curr->ifindex == ifindex)
	{
	  /* Unlink. Root ? */
	  if(!prev)
	    interface_cache = next;
	  else
	    prev->next = next;
	  //printf("Cache : purge %d-%s\n", curr->ifindex, curr->ifname);

	  /* Destroy */
	  free(curr);
	}
      else
	{
	  /* Keep as previous */
	  prev = curr;
	}

      /* Next entry */
      curr = next;
    }
}

/********************* WIRELESS EVENT DECODING *********************/
/*
 * Parse the Wireless Event and print it out
 */

/*------------------------------------------------------------------*/
/*
 * Dump a buffer as a serie of hex
 * Maybe should go in iwlib...
 * Maybe we should have better formatting like iw_print_key...
 */
static char *
iw_hexdump(char *		buf,
	   size_t		buflen,
	   const unsigned char *data,
	   size_t		datalen)
{
  size_t	i;
  char *	pos = buf;

  for(i = 0; i < datalen; i++)
    pos += snprintf(pos, buf + buflen - pos, "%02X", data[i]);
  return buf;
}

/*------------------------------------------------------------------*/
/*
 * Print one element from the scanning results
 */
static inline int
print_event_token(
		  const char * name,			/* Interface name */
		  struct iw_event *	event,		/* Extracted token */
		  struct iw_range *	iw_range,	/* Range info */
		  int			has_range)
{
  char		buffer[256];	/* Temporary buffer */
  char		buffer2[30];	/* Temporary buffer */
  static const int PRIO = LOG_DAEMON | LOG_INFO;

  if (event->cmd == IWEVCUSTOM &&
      (event->u.data.flags <  IW_SYSLOG_EVENT_MIN ||
       event->u.data.flags >= IW_SYSLOG_EVENT_MAX))
        return 0;

  /* Now, let's decode the event */
  switch(event->cmd)
    {
      /* ----- driver events ----- */
      /* Events generated by the driver when something important happens */
    case SIOCGIWAP:
      syslog(PRIO, "%s: new access point/cell address: %s.",
	     name, iw_sawap_ntop(&event->u.ap_addr, buffer));
      break;
    case SIOCGIWSCAN:
      syslog(PRIO, "%s: scan request completed.", name);
      break;
    case IWEVTXDROP:
      syslog(PRIO, "%s: TX packet dropped (%s).", name,
	    iw_saether_ntop(&event->u.addr, buffer));
      break;
    case IWEVCUSTOM:
      {
        static const char RAW_MSG[] = "RAWSCMSG";	// RaLink raw message ID.
        char custom[IW_CUSTOM_MAX+1];

        memset(custom, '\0', sizeof(custom));
        if((event->u.data.pointer) && (event->u.data.length))
          memcpy(custom, event->u.data.pointer,
            sizeof(custom) - 1 < event->u.data.length ?
            sizeof(custom) - 1 : event->u.data.length);

        if(strlen(custom) > 0) {
           if(strlen(custom) < sizeof(RAW_MSG) - 1 ||
              strncmp(custom, RAW_MSG, sizeof(RAW_MSG) - 1) != 0) {
             syslog(PRIO, "%s: %s.", name, custom);

             if (event->u.data.flags == IW_DEAUTH_EVENT_FLAG ||
                 event->u.data.flags == IW_AGEOUT_EVENT_FLAG ||
                 event->u.data.flags == IW_DISASSOC_EVENT_FLAG ||
                 event->u.data.flags == IW_ASSOC_EVENT_FLAG)
             {
                  char * regexString = MAC_REGEXP;
                  size_t maxGroups = 7;
				  char * name_dup = strdup(name);

                  regex_t regexCompiled;
                  regmatch_t groupArray[8];

                  if (name_dup == NULL)
                  {
                      syslog(PRIO, "Out of memory");
                  } else
                  if (regcomp(&regexCompiled, regexString, REG_EXTENDED))
                  {
                      syslog(PRIO, "Could not compile regular expression");
                  } else
                  if (regexec(&regexCompiled, custom, maxGroups, groupArray, 0) == 0)
                  {
                       char sta_mac[20];
                       char *p = sta_mac;
                       unsigned int g = 0;
                       unsigned int ctr = 0;

                       memset(sta_mac, 0, 20 * sizeof(char));

                       for (g = 1; g < maxGroups; g++)
                       {
                            if (groupArray[g].rm_so == (size_t)-1)
                                break;  // No more groups

                            if (groupArray[g].rm_eo - groupArray[g].rm_so != 2)
                                break;

                            char temp[3];

                            memset(temp, 0, 3 * sizeof(char));
                            strncpy(temp,
                                custom + groupArray[g].rm_so,
                                groupArray[g].rm_eo - groupArray[g].rm_so);
                            p += snprintf(p, 20, "%s:", temp);
                            ctr++;
                       }

                       if (ctr == 6)
                       {
                           *(p - 1) = '\0';

                           pid_t pid = fork();

                           if (pid == -1)
                           {
                               syslog(PRIO, "unable to fork");
                           } 
                           else if (pid > 0)
                           {
                              int status;
                              waitpid(pid, &status, 0);
                           }
                           else 
                           {
                               char *argv[] = {
                                   CLEANUP_FB,
                                   (event->u.data.flags == IW_ASSOC_EVENT_FLAG) ?
                                       "add" :
                                       "remove",
                                   name_dup,
                                   sta_mac, 0 };
                               char *envp[] = { 0 };

                               execve(argv[0], &argv[0], envp);
                               _exit(EXIT_FAILURE);
                           }
                       }
                  }

				  free(name_dup);
                  regfree(&regexCompiled);
             }
           }
        }
      }
      break;
    case IWEVREGISTERED:
      syslog(PRIO, "%s: registered node: %s.", name,
	     iw_saether_ntop(&event->u.addr, buffer));
      break;
    case IWEVEXPIRED:
      syslog(PRIO, "%s: expired node: %s.", name,
	     iw_saether_ntop(&event->u.addr, buffer));
      break;
    }	/* switch(event->cmd) */

  return(0);
}

/*------------------------------------------------------------------*/
/*
 * Print out all Wireless Events part of the RTNetlink message
 * Most often, there will be only one event per message, but
 * just make sure we read everything...
 */
static inline int
print_event_stream(int		ifindex,
		   char *	data,
		   int		len)
{
  struct iw_event	iwe;
  struct stream_descr	stream;
  int			i = 0;
  int			ret;
  struct timeval	recv_time;
  struct timezone	tz;
  struct wireless_iface *wireless_data;
  const char *alias = NULL;

  /* Get data from cache */
  wireless_data = iw_get_interface_data(ifindex);
  if(wireless_data == NULL)
    return(-1);

  iw_init_event_stream(&stream, data, len);
  do
    {
      /* Extract an event and print it */
      ret = iw_extract_event_stream(&stream, &iwe,
				    wireless_data->range.we_version_compiled);
      if(ret != 0)
	{
	  if(ret > 0) {
	    alias = _aliases_find(wireless_data->ifname);
	    print_event_token(
			      (alias == NULL) ? wireless_data->ifname : alias, &iwe,
			      &wireless_data->range, wireless_data->has_range);
	  }
	  else
	    fprintf(stderr, "invalid event\n");
	}
    }
  while(ret > 0);

  return(0);
}

/*********************** RTNETLINK EVENT DUMP***********************/
/*
 * Dump the events we receive from rtnetlink
 * This code is mostly from Casey
 */

/*------------------------------------------------------------------*/
/*
 * Respond to a single RTM_NEWLINK event from the rtnetlink socket.
 */
static int
LinkCatcher(struct nlmsghdr *nlh)
{
  struct ifinfomsg* ifi;

#if 0
  fprintf(stderr, "nlmsg_type = %d.\n", nlh->nlmsg_type);
#endif

  ifi = NLMSG_DATA(nlh);

  /* Code is ugly, but sort of works - Jean II */

  /* If interface is getting destoyed */
  if(nlh->nlmsg_type == RTM_DELLINK)
    {
      /* Remove from cache (if in cache) */
      iw_del_interface_data(ifi->ifi_index);
      return 0;
    }

  /* Only keep add/change events */
  if(nlh->nlmsg_type != RTM_NEWLINK)
    return 0;

  /* Check for attributes */
  if (nlh->nlmsg_len > NLMSG_ALIGN(sizeof(struct ifinfomsg)))
    {
      int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct ifinfomsg));
      struct rtattr *attr = (void *) ((char *) ifi +
				      NLMSG_ALIGN(sizeof(struct ifinfomsg)));

      while (RTA_OK(attr, attrlen))
	{
	  /* Check if the Wireless kind */
	  if(attr->rta_type == IFLA_WIRELESS)
	    {
	      /* Go to display it */
	      print_event_stream(ifi->ifi_index,
				 (char *) attr + RTA_ALIGN(sizeof(struct rtattr)),
				 attr->rta_len - RTA_ALIGN(sizeof(struct rtattr)));
	    }
	  attr = RTA_NEXT(attr, attrlen);
	}
    }

  return 0;
}

/* ---------------------------------------------------------------- */
/*
 * We must watch the rtnelink socket for events.
 * This routine handles those events (i.e., call this when rth.fd
 * is ready to read).
 */
static inline void
handle_netlink_events(struct rtnl_handle *	rth)
{
  while(1)
    {
      struct sockaddr_nl sanl;
      socklen_t sanllen = sizeof(struct sockaddr_nl);

      struct nlmsghdr *h;
      int amt;
      char buf[8192];

      amt = recvfrom(rth->fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&sanl, &sanllen);
      if(amt < 0)
	{
	  if(errno != EINTR && errno != EAGAIN)
	    {
	      fprintf(stderr, "%s: error reading netlink: %s.\n",
		      __PRETTY_FUNCTION__, strerror(errno));
	    }
	  return;
	}

      if(amt == 0)
	{
	  fprintf(stderr, "%s: EOF on netlink??\n", __PRETTY_FUNCTION__);
	  return;
	}

      h = (struct nlmsghdr*)buf;
      while(amt >= (int)sizeof(*h))
	{
	  int len = h->nlmsg_len;
	  int l = len - sizeof(*h);

	  if(l < 0 || len > amt)
	    {
	      fprintf(stderr, "%s: malformed netlink message: len=%d\n", __PRETTY_FUNCTION__, len);
	      break;
	    }

	  switch(h->nlmsg_type)
	    {
	    case RTM_NEWLINK:
	    case RTM_DELLINK:
	      LinkCatcher(h);
	      break;
	    default:
#if 0
	      fprintf(stderr, "%s: got nlmsg of type %#x.\n", __PRETTY_FUNCTION__, h->nlmsg_type);
#endif
	      break;
	    }

	  len = NLMSG_ALIGN(len);
	  amt -= len;
	  h = (struct nlmsghdr*)((char*)h + len);
	}

      if(amt > 0)
	fprintf(stderr, "%s: remnant of size %d on netlink\n", __PRETTY_FUNCTION__, amt);
    }
}

/**************************** MAIN LOOP ****************************/

/* ---------------------------------------------------------------- */
/*
 * Wait until we get an event
 */
static inline int
wait_for_event(struct rtnl_handle *	rth)
{
#if 0
  struct timeval	tv;	/* Select timeout */
#endif

  /* Forever */
  while(1)
    {
      struct pollfd pfd;	/* File descriptors for poll */
      int ret;
      int try_reload = 0;

      pfd.fd = rth->fd;
	  pfd.events = POLLIN | POLLERR;

      /* Wait until something happens;
	   * check _reload_map periodically. */
      ret = poll(&pfd, 1, 1000);

      /* Check if there was an error */
      if(ret < 0)
	{
	  if(errno == EAGAIN || errno == EINTR) {
	    try_reload = 1;
	  } else {
	    fprintf(stderr, "Unhandled signal - exiting...\n");
	    break;
	  }
	} else
	if(ret == 0) {
	  try_reload = 1;
	}

    if (try_reload && _reload_map) {
	  _reload_map = 0;

	  if (!_aliases_reload()) {
        fprintf(stderr, "Failed to reload aliases - exiting...\n");
		break;
	  }
	}

      /* Check if there was a timeout */
      if(ret == 0)
	{
	  continue;
	}

      /* Check for interface discovery events. */
	  if(ret > 0)
	    handle_netlink_events(rth);
    }

  return(0);
}

/******************************* MAIN *******************************/

/* ---------------------------------------------------------------- */
/*
 * helper ;-)
 */
static void
iw_usage(int status)
{
  fputs("Usage: wmond [OPTIONS]\n"
	"   Monitors and displays wireless events.\n"
	"   Options are:\n"
	"     -h,--help     Print this message.\n"
	"     -m,--mapfile  Interface alias map file.\n",
	status ? stderr : stdout);
  exit(status);
}
/* Command line options */
static const struct option long_opts[] = {
  { "help", no_argument, NULL, 'h' },
  { "map", required_argument, NULL, 'm' },
  { NULL, 0, NULL, 0 }
};

/* ---------------------------------------------------------------- */
/*
 * main body of the program
 */
int
main(int	argc,
     char *	argv[])
{
  struct rtnl_handle rth;
  int opt;
  sigset_t mask;
  struct sigaction action;
  const char *name = strrchr(argv[0], '/');
  const char *program = (name == NULL) ? argv[0] : name + 1;

  /* Check command line options */
  while((opt = getopt_long(argc, argv, "hm:", long_opts, NULL)) > 0)
    {
      switch(opt)
	{
	case 'h':
	  iw_usage(0);
	  break;

	case 'm':
	  _mapfile = optarg;
	  break;

	default:
	  iw_usage(1);
	  break;
	}
    }
  if(optind < argc)
    {
      fputs("Too many arguments.\n", stderr);
      iw_usage(1);
    }

  /* Open netlink channel */
  if(rtnl_open(&rth, RTMGRP_LINK) < 0)
    {
      perror("Can't initialize rtnetlink socket");
      return(1);
    }

  if (!_aliases_reload())
    {
	  errno = EINVAL;
      perror("Failed to load aliases");
      return(1);
    }

  memset(&action, 0, sizeof(action));
  sigemptyset(&mask);

  action.sa_handler = _sighup;
  action.sa_mask = mask;
  action.sa_flags = SA_RESTART;

  if(sigaction(SIGURG, &action, NULL) != 0)
    {
      perror("Can't initialize a signal handler");
      return(1);
    }

  openlog(program, LOG_NDELAY, LOG_DAEMON);
  fprintf(stderr, "Waiting for Wireless Events from interfaces...\n");

  /* Do what we have to do */
  wait_for_event(&rth);

  /* Cleanup - only if you are pedantic */
  rtnl_close(&rth);
  _aliases_free();
  closelog();

  return(0);
}
