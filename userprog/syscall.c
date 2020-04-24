#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
int sys_write(int fd, void *buffer, unsigned size);
void sys_exit (int status);

tid_t sys_exec(const char *cmd_line);

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
      f -> eax = sys_exec((char*)(*((int*)f->esp + 1)));
      break;
    }


  }


  //thread_exit ();
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

int sys_write(int fd, void *buffer, unsigned size){
	if (fd == 1){ // means stdout
		putbuf(buffer, size);
		return(size);
	} // for else need to figure out more stuff about file descriptors
}

void sys_exit (int status){
	struct thread *currentThread = thread_current();

	currentThread -> exit_status = status;
	printf ("%s: exit(%d)\n", currentThread -> name, status);
	// pass this status to a waiting parent
	thread_exit(); //cleanup and de-allocation and waiting for parent to reap exit status
}
