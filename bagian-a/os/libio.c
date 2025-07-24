# define _IO_acquire_lock(_fp)              \
  do {									                    \
    FILE *_IO_acquire_lock_file = NULL
# define _IO_release_lock(_fp)						  \
    if (_IO_acquire_lock_file != NULL)      \
      _IO_acquire_lock_file->_flags2 &= ~(_IO_FLAGS2_FORTIFY		    \
                                          | _IO_FLAGS2_SCANF_STD);  \
  } while (0)

  #define _IO_putc_unlocked(_ch, _fp) __putc_unlocked_body (_ch, _fp)

  #define __putc_unlocked_body(_ch, _fp)					\
  (__glibc_unlikely ((_fp)->_IO_write_ptr >= (_fp)->_IO_write_end)	\
   ? __overflow (_fp, (unsigned char) (_ch))				\
   : (unsigned char) (*(_fp)->_IO_write_ptr++ = (_ch)))