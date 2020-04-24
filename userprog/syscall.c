#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);
int sys_write(int fd, void *buffer, unsigned size);
void sys_exit (int status);

tid_t sys_exec(const char *cmd_line);
bool sys_create(const char *file, unsigned intial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall"); //Registering a handler for TRAP
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  //printf ("system call!\n");
  uint32_t callNo;
  uint32_t *user_esp = f -> esp;
  uint32_t arg1, arg2, arg3;


  //Might need more checks here to see if user_esp is valid 
  /* static inline bool is_user_vaddr (const void *vaddr)
  Returns true if VADDR is a user virtual address. */
  //basically checks if user_esp is below phys_base
  //Check that every possible value to be used is valid

  /*Looks up the physical address that corresponds to user virtual
   address UADDR in PD.  Returns the kernel virtual address
   corresponding to that physical address, or a null pointer if
   UADDR is unmapped. */
  //check if address is in a page

  //Need to find a better way of doing this, its pretty hacky and was just trying something out
  if(!is_user_vaddr(user_esp) || 
     !is_user_vaddr(user_esp + 1) || 
     !is_user_vaddr(user_esp + 2) || 
     !is_user_vaddr(user_esp + 3) || 
     pagedir_get_page(thread_current()->pagedir,user_esp)==NULL ||
     pagedir_get_page(thread_current()->pagedir,user_esp + 1)==NULL || 
     pagedir_get_page(thread_current()->pagedir,user_esp + 2)==NULL || 
     pagedir_get_page(thread_current()->pagedir,user_esp + 3)==NULL){
    sys_exit(-1);
  }

  callNo = (uint32_t)(*user_esp);
  //Hack because there might not be an arg1
  //Do a generic struct that knows how many arguments there are
  //Need to rewatch https://utexas.zoom.us/rec/play/75cvcbz7qz43EoGV5gSDC_VxW466fa2s1yBK8_tenk6xAHEBM1Sib-dBYbOqLbHUVWriBGOh0irr3VYV
  //https://static1.squarespace.com/static/5b18aa0955b02c1de94e4412/t/5b85fad2f950b7b16b7a2ed6/1535507195196/Pintos+Guide


  /*The caller pushes each of the function's arguments on the stack one by one, 
  normally using the PUSH assembly language instruction. Arguments are pushed in 
  right-to-left order.
  The stack grows downward: each push decrements the stack pointer, then stores 
  into the location it now points to, like the C expression *--sp = value.

  The caller pushes the address of its next instruction (the return address) on 
  the stack and jumps to the first instruction of the callee. A single 80x86 instruction, 
  CALL, does both.
  The callee executes. When it takes control, the stack pointer points to the return address, 
  the first argument is just above it, the second argument is just above the first argument, and so on.
  If the callee has a return value, it stores it into register EAX.
  The callee returns by popping the return address from the stack and jumping to the location 
  it specifies, using the 80x86 RET instruction.
  The caller pops the arguments off the stack.

  Stack looks something like this

                                   +----------------+
                        0xbffffe7c |        3       |
                        0xbffffe78 |        2       |
                        0xbffffe74 |        1       |
      stack pointer --> 0xbffffe70 | return address |
                                   +----------------+
  */

  /* Thus, when the system call handler syscall_handler() gets control, 
  the system call number is in the 32-bit word at the caller's stack pointer, 
  the first argument is in the 32-bit word at the next higher address, and so on. 
  The caller's stack pointer is accessible to syscall_handler() as the esp member of 
  the struct intr_frame passed to it. (struct intr_frame is on the kernel stack.)

The 80x86 convention for function return values is to place them in the EAX register. 
System calls that return a value can do so by modifying the eax member of struct intr_frame.

You should try to avoid writing large amounts of repetitive code for implementing system calls. 
Each system call argument, whether an integer or a pointer, takes up 4 bytes on the stack. You 
should be able to take advantage of this to avoid writing much near-identical code for retrieving 
each system call's arguments from the stack.*/

  switch(callNo){

  	case SYS_HALT: //Shutdown the machine
  	{
    	shutdown_power_off();
  		break;
    }

  	case SYS_WRITE:
    {  // Called to output to either a file or stdout. This is hack need to find a way to do it generically
      int fd = *((int*)f->esp + 1);
      void* buffer = (void*)(*((int*)f->esp + 2)); 
      unsigned size = *((unsigned*)f->esp + 3);
    	f -> eax = sys_write(fd, buffer, size);
    	break;
    }

  	case SYS_EXIT:
    {
  		user_esp++;
  		arg1 = (uint32_t)(*user_esp);
  		sys_exit(arg1); //arg1 has the exit status in it
  		break;
    }

    case SYS_EXEC:
    {
      //Still need to finish implementation of this
      //Looks like it prints stuff out write 
      //but never terminates
      //probably needs wait to be implemented
      f -> eax = sys_exec((char*)(*((int*)f->esp + 1)));
      break;
    }

    case SYS_CREATE:
    {
      f -> eax = sys_create((char*)(*((int*)f->esp + 1)), *((unsigned*)f->esp + 2));
      break;
    }

    case SYS_REMOVE: 
    {
      //f -> eax = sys_remove((char*)(*((int*)f->esp + 1)));
      break;
    }

    case SYS_OPEN: 
    {
      //f -> eax = sys_open((char*)(*((int*)f->esp + 1)));
      break;
    }

    case SYS_WAIT: 
    {
      //f -> eax = sys_open((char*)(*((int*)f->esp + 1)));
      break;
    }

    case SYS_READ:
    {
      break;
    }

    case SYS_FILESIZE:
    {
      break;
    }

    case SYS_SEEK:
    {
      break;
    }

    case SYS_TELL:
    {
      break;
    }

    case SYS_CLOSE:
    {
      break;
    }


  }


  //thread_exit ();
}


/*System Call: int open (const char *file)
Opens the file called file. Returns a nonnegative integer 
handle called a "file descriptor" (fd), or -1 if the file could not be opened.
File descriptors numbered 0 and 1 are reserved for the console: 
fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output. 
The open system call will never return either of these file descriptors, which are 
valid as system call arguments only as explicitly described below.

Each process has an independent set of file descriptors. File descriptors are not 
inherited by child processes.

When a single file is opened more than once, whether by a single process or 
different processes, each open returns a new file descriptor. Different file 
descriptors for a single file are closed independently in separate calls to close 
and they do not share a file position.*/

int sys_open(const char *file){
  /* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */

  //struct file *filesys_open (const char *name)

  return filesys_open(file);
}

/*System Call: bool remove (const char *file)
Deletes the file called file. Returns true if successful, 
false otherwise. A file may be removed regardless of whether 
it is open or closed, and removing an open file does not close 
it. See Removing an Open File, for details.*/

bool sys_remove(const char *file){
  /* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
  
  //bool filesys_remove (const char *name)

  return filesys_remove(file);
}


/*System Call: bool create (const char *file, unsigned initial_size)
Creates a new file called file initially initial_size bytes in size. 
Returns true if successful, false otherwise. Creating a new file does 
not open it: opening the new file is a separate operation which would 
require a open system call.*/

bool sys_create(const char *file, unsigned intial_size){
  /* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */

   // bool filesys_create (const char *name, off_t initial_size)

  return filesys_create(file, intial_size);
}

/*System Call: int filesize (int fd)
Returns the size, in bytes, of the file open as fd.*/

int sys_filesize(int fd){

}

/*System Call: int read (int fd, void *buffer, unsigned size)
Reads size bytes from the file open as fd into buffer. Returns 
the number of bytes actually read (0 at end of file), or -1 if 
the file could not be read (due to a condition other than end of file). 
Fd 0 reads from the keyboard using input_getc().*/

int sys_read(int fd, void *buffer, unsigned size){

}


/*System Call: pid_t exec (const char *cmd_line)
Runs the executable whose name is given in cmd_line, passing any given arguments, 
and returns the new process's program id (pid). Must return pid -1, which otherwise 
should not be a valid pid, if the program cannot load or run for any reason. Thus, 
the parent process cannot return from the exec until it knows whether the child process 
successfully loaded its executable. You must use appropriate synchronization to ensure this.*/

tid_t sys_exec(const char *cmd_line){
  return process_execute (cmd_line);

}

/*System Call: int wait (pid_t pid)
Waits for a child process pid and retrieves the child's exit status.
If pid is still alive, waits until it terminates. Then, returns the status that 
pid passed to exit. If pid did not call exit(), but was terminated by the kernel 
(e.g. killed due to an exception), wait(pid) must return -1. It is perfectly legal 
for a parent process to wait for child processes that have already terminated by the 
time the parent calls wait, but the kernel must still allow the parent to retrieve its 
child's exit status, or learn that the child was terminated by the kernel.

wait must fail and return -1 immediately if any of the following conditions is true:

pid does not refer to a direct child of the calling process. pid is a direct child of 
the calling process if and only if the calling process received pid as a return value f
rom a successful call to exec.
Note that children are not inherited: if A spawns child B and B spawns child process C, 
then A cannot wait for C, even if B is dead. A call to wait(C) by process A must fail. 
Similarly, orphaned processes are not assigned to a new parent if their parent process 
exits before they do.

The process that calls wait has already called wait on pid. That is, a process may 
wait for any given child at most once.
Processes may spawn any number of children, wait for them in any order, and may even 
exit without having waited for some or all of their children. Your design should consider 
all the ways in which waits can occur. All of a process's resources, including its struct 
thread, must be freed whether its parent ever waits for it or not, and regardless of whether
 the child exits before or after its parent.

You must ensure that Pintos does not terminate until the initial process exits. The 
supplied Pintos code tries to do this by calling process_wait() (in userprog/process.c) 
from main() (in threads/init.c). We suggest that you implement process_wait() according 
to the comment at the top of the function and then implement the wait system call in terms of process_wait().

Implementing this system call requires considerably more work than any of the rest.*/

int sys_wait (tid_t pid){

}

/*System Call: int write (int fd, const void *buffer, unsigned size)
Writes size bytes from buffer to the open file fd. Returns the number 
of bytes actually written, which may be less than size if some bytes 
could not be written.
Writing past end-of-file would normally extend the file, but file growth 
is not implemented by the basic file system. The expected behavior is to 
write as many bytes as possible up to end-of-file and return the actual 
number written, or 0 if no bytes could be written at all.

Fd 1 writes to the console. Your code to write to the console should 
write all of buffer in one call to putbuf(), at least as long as size is
 not bigger than a few hundred bytes. (It is reasonable to break up larger 
 buffers.) Otherwise, lines of text output by different processes may end up 
 interleaved on the console, confusing both human readers and our grading scripts.*/

int sys_write(int fd, void *buffer, unsigned size){
	if (fd == 1){ // means stdout
		putbuf(buffer, size);
		return(size);
	} // for else need to figure out more stuff about file descriptors
}


/*System Call: void exit (int status)
Terminates the current user program, returning status to the kernel. 
If the process's parent waits for it (see below), this is the status 
that will be returned. Conventionally, a status of 0 indicates success 
and nonzero values indicate errors.*/

void sys_exit (int status){
	struct thread *currentThread = thread_current();

	currentThread -> exit_status = status;
	printf ("%s: exit(%d)\n", currentThread -> name, status);
	// pass this status to a waiting parent
	thread_exit(); //cleanup and de-allocation and waiting for parent to reap exit status
}

/*System Call: void seek (int fd, unsigned position)
Changes the next byte to be read or written in open file fd to position, 
expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.)
A seek past the current end of a file is not an error. A later read obtains 0 bytes, 
indicating end of file. A later write extends the file, filling any unwritten gap with zeros.
 (However, in Pintos files have a fixed length until project 4 is complete, so writes past end 
 of file will return an error.) These semantics are implemented in the file system and do not 
 require any special effort in system call implementation.*/

void sys_seek(int fd, unsigned position){

}


/*System Call: unsigned tell (int fd)
Returns the position of the next byte to be read or written in open file fd, expressed 
in bytes from the beginning of the file.*/

unsigned sys_tell(int fd){

}


/*System Call: void close (int fd)
Closes file descriptor fd. Exiting or terminating a process implicitly closes 
all its open file descriptors, as if by calling this function for each one.*/

void sys_close(int fd){

}
