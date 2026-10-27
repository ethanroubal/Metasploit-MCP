"""Internal exec helper: attach the supplied slave PTY as the controlling terminal."""
import fcntl
import os
import sys
import termios


def main():
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    os.tcsetpgrp(0, os.getpgrp())
    os.execvpe(sys.argv[1], sys.argv[1:], os.environ)


if __name__ == "__main__":
    main()
