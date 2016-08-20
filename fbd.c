#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/current.h>
#include <asm/pgtable.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/syscall.h>
#include <linux/string.h>
#include <linux/pid.h>
/*
 *Parameter Declarations
 */
                                    //particular period of time ex:1 milli second
static int interval=1000; 
module_param(interval, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(interval, "rate of time");

static int threshold=100; //maximum number of process allowed in the time intervel
module_param(threshold, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(threshold, "no of processes");


static int ste=1;   // this is for check conditions
module_param(ste, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(ste, "status");


static unsigned long ere=1; //storing the start time of fork bomb process
module_param(ere, ulong, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(ere, "time");

asmlinkage int (*old_clone)(struct pt_regs args); //Original clone declaration 


//syscalltable address note:system call table address may different for every host
unsigned long *syscalltable = (unsigned long *)0xc1697140;

//storing fork bomb process name
static char *name="hqwaew";
module_param(name, charp , S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(name, "command name");


/*
 * Overriding clone
 */


// new clone function
asmlinkage int new_clone(struct pt_regs args) {  
   
  //storing cuurent process name
   char buf[100]; 

  //declaring task_struct type
   struct task_struct *process;

   unsigned long now = 0,nowu=0,end=0;//this is for storing time(jiffies)

   int  nprocesses = 0,ppid=0,ft=0;//for caluculating purpose only

   struct pid *pspid;//declaring pid struct type for killing fork bomb process

   struct task_struct *cur=current;//it returns current process request

   strcpy(buf,current->comm);//storing current process name into buffer array

  /*
   //below code storing current process start time 
   if(strcmp(cur->comm,"a.out")==0 && ste==1){
    ere=jiffies_to_nsecs(jiffies);
    printk(KERN_ALERT "start %lu\n",ere);
    ste=0;    
    } */
    
   //this below comment lines related to memory
    //printk(KERN_ALERT "calling value %s:%d name value:%s number:%d \n",cur->comm,strcmp(cur->comm,name),*name,current->mm->total_vm);
   // printk(KERN_ALERT "data:%d rss:%lu\n",(current->mm->mmap->vm_start)-(current->mm->mmap->vm_end),current->mm->map_count);
    //printk(KERN_ALERT "mm data:%d\n",(current->mm->start_data)-(current->mm->end_data));
    

    //it checks current process name is fork bomb process
    if(strcmp(cur->comm,name)!=0){
          
           
	   
            //travesre processes linked list
	    for_each_process(process) {
			

                         //it checks number of process execeeds threshold value
                         if(nprocesses >= threshold && strcmp(buf,cur->comm)==0 ) {


                                // below code displays the detection time(testing purpose only)
		               // printk(KERN_ALERT "under denied system %s\n",cur->comm);
                                /*if(ft==0){
                                  end=jiffies_to_nsecs(jiffies);
                                  printk(KERN_ALERT "end %lu\n",end);
                                  nowu=end-ere;
		                printk(KERN_ALERT "time %lu\n",nowu);
                                  ft=1;
                                     }*/

                                //once detects it stores the process name into global variable
				name=process->comm;

				return -EAGAIN;//blocking the current request
			}
			 
                         //it checks the number of process created in particualar period of time(1ms)
			 else if(strcmp(buf,process->comm)==0 && 0<(now - (process->start_time.tv_nsec/1000000)) <= interval ){
			                 
					  nprocesses++;//storing number of processes created
					  
			 }
			
			
			


	    }

	   //if not satisfied above conditions i.e, it is not fork bomb process safely allows current request
           //return arguments to original clone function
	    return (*old_clone)(args);
	    
	    
	}
	
	//again get a new request from fork bomb processes(after detecting process is fork bomb process) this condition is executed
	else{
	
		  
                 // get the parent id of the fork bomb process 
		  while( cur->pid !=0 &&  strcmp(name,cur->comm)==0 ) {
		  
					ppid=cur->pid;
					cur=cur->parent;
		  }
		  
                 // display parent process id and its process name	
		  printk(KERN_ALERT "FBD!: please kill that process %d. please execute command  `killall -9 %s`. it creates fork bomb \n", ppid,current->comm);
                  
                 // this code kills fork bomb process
                  pspid = find_vpid(current->pid);	
		  kill_pid(pspid,9,1);
                 
		  return -EAGAIN;
	 
	}


}

/*
 * Module initialization
 */


static int load_new_module(void) {
	printk(KERN_ALERT "FBD: Loading module\n");
	printk(KERN_ALERT "FBD: threshold %d.\n", threshold);
	printk(KERN_ALERT "FBD: interval %d.\n", interval);
	

        /* disable protected mode system table
 
   I perform a not operation to 0x10000 ( so I have 0x01111).
   Later I perform an AND operation between the current value
   of the CR0 register and 0x01111. So the WP bit is set to 0
   and the protected mode is disabled.
 
     */
	write_cr0(read_cr0() & (~0x10000));
	
       //overriding old clone function to new clone function
	old_clone = (void *)syscalltable[__NR_clone];
	syscalltable[__NR_clone] = (sys_call_ptr_t)new_clone;
	

       /* enable protected mode system table
 
   I perform an OR operation between the current value of
   the CR0 register and 0x10000. So the WP bit is set to 1
   and the protected mode is enabled.
    
    */
	write_cr0(read_cr0() | (0x10000));
	
	return 0;

}

/*
 * Unloading module
 */

static void unload_new_module(void) {
	printk(KERN_ALERT "FBD: Unloading module\n");

        /* disable protected mode system table
 
   I perform a not operation to 0x10000 ( so I have 0x01111).
   Later I perform an AND operation between the current value
   of the CR0 register and 0x01111. So the WP bit is set to 0
   and the protected mode is disabled.
 
     */
	write_cr0(read_cr0() & (~0x10000));
	
     //when unloading module set to original clone function
	syscalltable[__NR_clone] = (sys_call_ptr_t)old_clone;
 
       /* enable protected mode system table
 
   I perform an OR operation between the current value of
   the CR0 register and 0x10000. So the WP bit is set to 1
   and the protected mode is enabled.
    
     */
	write_cr0(read_cr0() | (0x10000));
	return;
}

//module initialization
module_init(load_new_module);

//module exit
module_exit(unload_new_module);
MODULE_LICENSE("GPL");
