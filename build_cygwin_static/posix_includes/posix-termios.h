
#ifdef __cplusplus
extern "C" {
#endif

/* posix-termios.h - Strict C89 Header */
/**
 * @file posix-termios.h
 * @brief POSIX termios API implementation for native MSVC.
 *
 * This header provides the POSIX termios interface, types, and macros.
 */
#ifndef POSIX_TERMIOS_H
#define POSIX_TERMIOS_H

/**
 * @brief Terminal flag type.
 */
typedef unsigned int tcflag_t;

/**
 * @brief Terminal special character type.
 */
typedef unsigned char cc_t;

/**
 * @brief Terminal speed type.
 */
typedef unsigned int speed_t;

#ifndef _PID_T_DEFINED
#define _PID_T_DEFINED
/**
 * @brief Process ID type.
 */
typedef int pid_t;
#endif

/**
 * @brief Number of special characters in termios.c_cc.
 */
#define NCCS 32

/**
 * @brief POSIX termios structure for terminal I/O attributes.
 */
struct termios {
  tcflag_t c_iflag; /**< input modes */
  tcflag_t c_oflag; /**< output modes */
  tcflag_t c_cflag; /**< control modes */
  tcflag_t c_lflag; /**< local modes */
  cc_t c_cc[NCCS];  /**< special characters */
  speed_t c_ispeed; /**< input speed */
  speed_t c_ospeed; /**< output speed */
};

/* c_iflag bits */
#define IGNBRK 0000001  /**< Ignore break condition */
#define BRKINT 0000002  /**< Signal interrupt on break */
#define IGNPAR 0000004  /**< Ignore characters with parity errors */
#define PARMRK 0000010  /**< Mark parity errors */
#define INPCK 0000020   /**< Enable input parity check */
#define ISTRIP 0000040  /**< Strip 8th bit off characters */
#define INLCR 0000100   /**< Map NL to CR on input */
#define IGNCR 0000200   /**< Ignore CR */
#define ICRNL 0000400   /**< Map CR to NL on input */
#define IXON 0001000    /**< Enable start/stop output control */
#define IXANY 0002000   /**< Enable any character to restart output */
#define IXOFF 0004000   /**< Enable start/stop input control */
#define IMAXBEL 0010000 /**< Ring bell when input queue is full */
#define IUTF8 0020000   /**< Input is UTF8 */

/* c_oflag bits */
#define OPOST 0000001  /**< Post-process output */
#define ONLCR 0000002  /**< Map NL to CR-NL on output */
#define OXTABS 0000004 /**< Expand tabs to spaces */
#define ONOEOT 0000010 /**< Discard EOT (^D) on output */
#define OCRNL 0000020  /**< Map CR to NL on output */
#define ONOCR 0000040  /**< No CR output at column 0 */
#define ONLRET 0000100 /**< NL performs CR function */

/* c_cflag bits */
#define CSIZE 0000060  /**< Character size mask */
#define CS5 0000000    /**< 5 bits (pseudo) */
#define CS6 0000020    /**< 6 bits */
#define CS7 0000040    /**< 7 bits */
#define CS8 0000060    /**< 8 bits */
#define CSTOPB 0000100 /**< Send two stop bits, else one */
#define CREAD 0000200  /**< Enable receiver */
#define PARENB 0000400 /**< Parity enable */
#define PARODD 0001000 /**< Odd parity, else even */
#define HUPCL 0002000  /**< Hang up on last close */
#define CLOCAL 0004000 /**< Ignore modem status lines */

/* c_lflag bits */
#define ISIG 0000001   /**< Enable signals INTR, QUIT, [D]SUSP */
#define ICANON 0000002 /**< Canonical input (erase and kill processing) */
#define ECHO 0000010   /**< Enable echo */
#define ECHOE                                                                  \
  0000020              /**< Echo erase character as error-correcting backspace \
                        */
#define ECHOK 0000040  /**< Echo KILL */
#define ECHONL 0000100 /**< Echo NL */
#define NOFLSH 0000200 /**< Disable flush after interrupt or quit */
#define TOSTOP 0000400 /**< Send SIGTTOU for background output */
#define IEXTEN 0001000 /**< Enable extended functions */

/* c_cc characters */
#define VEOF 0      /**< EOF character */
#define VEOL 1      /**< EOL character */
#define VEOL2 2     /**< EOL2 character */
#define VERASE 3    /**< ERASE character */
#define VWERASE 4   /**< WERASE character */
#define VKILL 5     /**< KILL character */
#define VREPRINT 6  /**< REPRINT character */
#define VSWTC 7     /**< SWTC character */
#define VINTR 8     /**< INTR character */
#define VQUIT 9     /**< QUIT character */
#define VSUSP 10    /**< SUSP character */
#define VSTART 12   /**< START character */
#define VSTOP 13    /**< STOP character */
#define VLNEXT 14   /**< LNEXT character */
#define VDISCARD 15 /**< DISCARD character */
#define VMIN 16     /**< MIN value */
#define VTIME 17    /**< TIME value */

/* tcsetattr uses these */
#define TCSANOW 0   /**< Make change immediately */
#define TCSADRAIN 1 /**< Drain output, then change */
#define TCSAFLUSH 2 /**< Drain output, flush input */

/* tcflow() uses these */
#define TCOOFF 0 /**< Suspend output */
#define TCOON 1  /**< Restart output */
#define TCIOFF 2 /**< Transmit STOP character */
#define TCION 3  /**< Transmit START character */

/* tcflush() uses these */
#define TCIFLUSH 0  /**< Flush pending input */
#define TCOFLUSH 1  /**< Flush untransmitted output */
#define TCIOFLUSH 2 /**< Flush both pending input and untransmitted output */

/* baud rates */
#define B0 0000000     /**< Hang up */
#define B50 0000001    /**< 50 baud */
#define B75 0000002    /**< 75 baud */
#define B110 0000003   /**< 110 baud */
#define B134 0000004   /**< 134.5 baud */
#define B150 0000005   /**< 150 baud */
#define B200 0000006   /**< 200 baud */
#define B300 0000007   /**< 300 baud */
#define B600 0000010   /**< 600 baud */
#define B1200 0000011  /**< 1200 baud */
#define B1800 0000012  /**< 1800 baud */
#define B2400 0000013  /**< 2400 baud */
#define B4800 0000014  /**< 4800 baud */
#define B9600 0000015  /**< 9600 baud */
#define B19200 0000016 /**< 19200 baud */
#define B38400 0000017 /**< 38400 baud */

/**
 * @brief Get input baud rate.
 * @param termios_p Pointer to termios structure.
 * @return Input speed.
 */
speed_t cfgetispeed(const struct termios *termios_p);

/**
 * @brief Get output baud rate.
 * @param termios_p Pointer to termios structure.
 * @return Output speed.
 */
speed_t cfgetospeed(const struct termios *termios_p);

/**
 * @brief Set input baud rate.
 * @param termios_p Pointer to termios structure.
 * @param speed Speed to set.
 * @return 0 on success, -1 on failure.
 */
int cfsetispeed(struct termios *termios_p, speed_t speed);

/**
 * @brief Set output baud rate.
 * @param termios_p Pointer to termios structure.
 * @param speed Speed to set.
 * @return 0 on success, -1 on failure.
 */
int cfsetospeed(struct termios *termios_p, speed_t speed);

/**
 * @brief Wait for all output to be transmitted.
 * @param fd File descriptor.
 * @return 0 on success, -1 on failure.
 */
int tcdrain(int fd);

/**
 * @brief Suspend or restart transmission.
 * @param fd File descriptor.
 * @param action Action to perform.
 * @return 0 on success, -1 on failure.
 */
int tcflow(int fd, int action);

/**
 * @brief Discard non-transmitted output data, non-read input data, or both.
 * @param fd File descriptor.
 * @param queue_selector Queue to flush.
 * @return 0 on success, -1 on failure.
 */
int tcflush(int fd, int queue_selector);

/**
 * @brief Get parameters associated with the terminal.
 * @param fd File descriptor.
 * @param termios_p Pointer to termios structure.
 * @return 0 on success, -1 on failure.
 */
int tcgetattr(int fd, struct termios *termios_p);

/**
 * @brief Get process group ID of the session leader.
 * @param fd File descriptor.
 * @return Process group ID on success, -1 on failure.
 */
pid_t tcgetsid(int fd);

/**
 * @brief Send a break for a specific duration.
 * @param fd File descriptor.
 * @param duration Duration of the break.
 * @return 0 on success, -1 on failure.
 */
int tcsendbreak(int fd, int duration);

/**
 * @brief Set parameters associated with the terminal.
 * @param fd File descriptor.
 * @param optional_actions When to apply the changes.
 * @param termios_p Pointer to termios structure.
 * @return 0 on success, -1 on failure.
 */
int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* POSIX_TERMIOS_H */
