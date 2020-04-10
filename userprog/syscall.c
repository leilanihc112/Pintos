#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
int sys_write(int fd, void *buffer, unsigned size);
void sys_exit (int status);

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

  callNo = (uint32_t)(*user_esp);
  //Hack because there might not be an arg1
  //Do a generic struct that knows how many arguments there are

  switch(callNo){

  	case SYS_HALT: //Shutdown the machine
  		shutdown_power_off();
  		break;

  	case SYS_WRITE: // Called to output to either a file or stdout. This is hack need to find a way to do it generically
  		user_esp++;
  		arg1 = (uint32_t)(*user_esp);
  		user_esp++;
  		arg2 = (uint32_t)(*user_esp);
  		user_esp++;
  		arg3 = (uint32_t)(*user_esp);
  		f -> eax = sys_write((int)arg1, (char *)arg2, (unsigned)arg3);
  		break;

  	case SYS_EXIT:
  		user_esp++;
  		arg1 = (uint32_t)(*user_esp);
  		sys_exit(arg1); //arg1 has the exit status in it
  		break;
  }


  //thread_exit ();
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
