/**
 * @file posix-ipc.h
 * @brief Strict C89 Header for POSIX IPC (Inter-Process Communication) on MSVC.
 *
 * Provides a POSIX-compliant interface for System V message queues, semaphore
 * sets, and shared memory segments, specifically tailored for native Windows
 * (MSVC) compatibility.
 */
#ifndef POSIX_IPC_H
#define POSIX_IPC_H

/* clang-format off */
#include <stddef.h>
#include <time.h>

#ifdef _WIN32

#ifdef _MSC_VER
#ifndef _SSIZE_T_DEFINED
#ifdef _WIN64
typedef __int64 ssize_t;
#else
typedef int ssize_t;
#endif
#define _SSIZE_T_DEFINED
#endif
#endif /* _MSC_VER */

#ifndef _PID_T_DEFINED
/** @brief Process ID type. */
typedef int pid_t;
#define _PID_T_DEFINED
#endif

#ifndef _UID_T_DEFINED
/** @brief User ID type. */
typedef int uid_t;
#define _UID_T_DEFINED
#endif

#ifndef _GID_T_DEFINED
/** @brief Group ID type. */
typedef int gid_t;
#define _GID_T_DEFINED
#endif

#ifndef _KEY_T_DEFINED
/** @brief IPC Key type. */
typedef int key_t;
#define _KEY_T_DEFINED
#endif

#else /* !_WIN32 */
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/types.h>
/* clang-format on */

#ifdef __cplusplus
extern "C" {
#endif

#endif /* !_WIN32 */

#ifdef _WIN32

/* IPC Flags */
#define IPC_CREAT 0001000  /**< @brief Create if key is nonexistent */
#define IPC_EXCL 0002000   /**< @brief Fail if key exists */
#define IPC_NOWAIT 0004000 /**< @brief Return error on wait */

#define IPC_PRIVATE                                                            \
  ((key_t)0)       /**< @brief Private key for unique IPC object               \
                    */
#define IPC_RMID 0 /**< @brief Remove IPC resource */
#define IPC_SET 1  /**< @brief Set ipc_perm options */
#define IPC_STAT 2 /**< @brief Get ipc_perm options */

/* Semaphore operation flags */
#define SEM_UNDO 0x1000 /**< @brief Undo semaphore operation on exit */

/* Semaphore control commands */
#define GETPID 11 /**< @brief Get PID of last operation */
#define GETVAL 12 /**< @brief Get semaphore value */
#define GETALL 13 /**< @brief Get all semaphore values */
#define GETNCNT                                                                \
  14               /**< @brief Get number of waiting processes for increment   \
                    */
#define GETZCNT 15 /**< @brief Get number of waiting processes for zero */
#define SETVAL 16  /**< @brief Set semaphore value */
#define SETALL 17  /**< @brief Set all semaphore values */

/* Message flags */
#define MSG_NOERROR 010000 /**< @brief Truncate message if too large */

/* Shared memory commands */
#define SHM_RDONLY 010000 /**< @brief Attach shared memory read-only */

/**
 * @struct ipc_perm
 * @brief IPC permissions structure.
 */
struct ipc_perm {
  uid_t uid;            /**< @brief Owner's user ID */
  gid_t gid;            /**< @brief Owner's group ID */
  uid_t cuid;           /**< @brief Creator's user ID */
  gid_t cgid;           /**< @brief Creator's group ID */
  unsigned short mode;  /**< @brief Read/write permission */
  unsigned short __seq; /**< @brief Sequence number */
};

/**
 * @struct msqid_ds
 * @brief Message queue data structure.
 */
struct msqid_ds {
  struct ipc_perm msg_perm; /**< @brief Operation permission struct */
  time_t msg_stime;         /**< @brief Time of last msgsnd */
  time_t msg_rtime;         /**< @brief Time of last msgrcv */
  time_t msg_ctime;         /**< @brief Time of last change */
  unsigned long msg_cbytes; /**< @brief Current number of bytes on queue */
  unsigned long msg_qnum;   /**< @brief Current number of messages on queue */
  unsigned long
      msg_qbytes;  /**< @brief Maximum number of bytes allowed on queue */
  pid_t msg_lspid; /**< @brief PID of last msgsnd */
  pid_t msg_lrpid; /**< @brief PID of last msgrcv */
};

/**
 * @struct semid_ds
 * @brief Semaphore set data structure.
 */
struct semid_ds {
  struct ipc_perm sem_perm; /**< @brief Operation permission struct */
  time_t sem_otime;         /**< @brief Time of last semop */
  time_t sem_ctime;         /**< @brief Time of last change */
  unsigned long sem_nsems;  /**< @brief Number of semaphores in set */
};

/**
 * @struct shmid_ds
 * @brief Shared memory data structure.
 */
struct shmid_ds {
  struct ipc_perm shm_perm; /**< @brief Operation permission struct */
  size_t shm_segsz;         /**< @brief Size of segment in bytes */
  time_t shm_atime;         /**< @brief Time of last shmat */
  time_t shm_dtime;         /**< @brief Time of last shmdt */
  time_t shm_ctime;         /**< @brief Time of last change */
  pid_t shm_cpid;           /**< @brief PID of creator */
  pid_t shm_lpid;           /**< @brief PID of last shmat/shmdt */
  unsigned long shm_nattch; /**< @brief Number of current attaches */
};

/**
 * @struct sembuf
 * @brief Semaphore operation structure.
 */
struct sembuf {
  unsigned short sem_num; /**< @brief Semaphore number */
  short sem_op;           /**< @brief Semaphore operation */
  short sem_flg;          /**< @brief Operation flags */
};

/**
 * @brief Converts a pathname and a project identifier to a System V IPC key.
 * @param path The pathname to a real file.
 * @param id The project identifier.
 * @return The generated IPC key, or (key_t)-1 on failure.
 */
key_t ftok(const char *path, int id);

/**
 * @brief Performs control operations on a message queue.
 * @param msqid The message queue identifier.
 * @param cmd The control command to execute (e.g., IPC_RMID, IPC_STAT).
 * @param buf Pointer to a msqid_ds structure for status or set operations.
 * @return 0 on success, -1 on failure.
 */
int msgctl(int msqid, int cmd, struct msqid_ds *buf);

/**
 * @brief Gets a System V message queue identifier.
 * @param key The IPC key.
 * @param msgflg Message flags and permissions.
 * @return A valid message queue identifier on success, -1 on failure.
 */
int msgget(key_t key, int msgflg);

/**
 * @brief Receives a message from a System V message queue.
 * @param msqid The message queue identifier.
 * @param msgp Pointer to a message buffer (must start with long mtype).
 * @param msgsz Maximum size of the message text to receive.
 * @param msgtyp The type of message to receive.
 * @param msgflg Operation flags (e.g., IPC_NOWAIT).
 * @return The number of bytes copied into the message buffer, or -1 on failure.
 */
ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);

/**
 * @brief Sends a message to a System V message queue.
 * @param msqid The message queue identifier.
 * @param msgp Pointer to a message buffer (must start with long mtype).
 * @param msgsz Size of the message text.
 * @param msgflg Operation flags (e.g., IPC_NOWAIT).
 * @return 0 on success, -1 on failure.
 */
int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);

/**
 * @brief Performs control operations on a System V semaphore set.
 * @param semid The semaphore set identifier.
 * @param semnum The specific semaphore number within the set.
 * @param cmd The control command to execute.
 * @param ... Optional fourth argument (union semun) depending on cmd.
 * @return A non-negative value on success (depending on cmd), -1 on failure.
 */
int semctl(int semid, int semnum, int cmd, ...);

/**
 * @brief Gets a System V semaphore set identifier.
 * @param key The IPC key.
 * @param nsems Number of semaphores in the set.
 * @param semflg Semaphore flags and permissions.
 * @return A valid semaphore set identifier on success, -1 on failure.
 */
int semget(key_t key, int nsems, int semflg);

/**
 * @brief Performs operations on selected System V semaphores.
 * @param semid The semaphore set identifier.
 * @param sops Pointer to an array of sembuf structures.
 * @param nsops Number of operations in the array.
 * @return 0 on success, -1 on failure.
 */
int semop(int semid, struct sembuf *sops, size_t nsops);

/**
 * @brief Attaches a System V shared memory segment to the calling process.
 * @param shmid The shared memory segment identifier.
 * @param shmaddr The requested attach address (usually NULL).
 * @param shmflg Attach flags (e.g., SHM_RDONLY).
 * @return A pointer to the attached segment on success, or (void*)-1 on
 * failure.
 */
void *shmat(int shmid, const void *shmaddr, int shmflg);

/**
 * @brief Performs control operations on a System V shared memory segment.
 * @param shmid The shared memory segment identifier.
 * @param cmd The control command to execute (e.g., IPC_RMID).
 * @param buf Pointer to a shmid_ds structure for status or set operations.
 * @return 0 on success, -1 on failure.
 */
int shmctl(int shmid, int cmd, struct shmid_ds *buf);

/**
 * @brief Detaches a System V shared memory segment from the calling process.
 * @param shmaddr The address of the attached segment.
 * @return 0 on success, -1 on failure.
 */
int shmdt(const void *shmaddr);

/**
 * @brief Gets a System V shared memory segment identifier.
 * @param key The IPC key.
 * @param size Minimum size of the segment in bytes.
 * @param shmflg Shared memory flags and permissions.
 * @return A valid shared memory segment identifier on success, -1 on failure.
 */
int shmget(key_t key, size_t size, int shmflg);

#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_IPC_H */
