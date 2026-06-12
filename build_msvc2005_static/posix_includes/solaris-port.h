
#ifdef __cplusplus
extern "C" {
#endif

#ifndef SOLARIS_PORT_H
#define SOLARIS_PORT_H

#if defined(_MSC_VER) && !defined(__clang__)
struct port_event {
  int portev_events;
  unsigned short portev_source;
  unsigned short portev_pad;
  unsigned int portev_object;
  void *portev_user;
};
/** \brief port_create function. */
int port_create(void);
/** \brief port_associate function. */
int port_associate(int port, int source, unsigned int object, int events,
                   void *user);
struct timespec;
/** \brief port_getn function. */
int port_getn(int port, struct port_event *list, unsigned int max,
              unsigned int *nget, const struct timespec *timeout);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
