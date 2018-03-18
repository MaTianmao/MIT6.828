#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};

extern void divide_error();
extern void debug_error();
extern void non_maskable_interrupt();
extern void break_point();
extern void over_flow();
extern void bound_range_exceeded();
extern void invalid_opcode();
extern void device_not_available();
extern void double_fault();
extern void invalid_tss();
extern void segment_not_present();
extern void stack_fault();
extern void general_protection();
extern void page_fault();
extern void x87_fpu_floating_point_error();
extern void alignment_check();
extern void machine_check(); 	 	
extern void simd_floating_point_exception();
extern void sys_call();

extern void vector0();
extern void vector1();
extern void vector2();
extern void vector3();
extern void vector4();
extern void vector5();
extern void vector6();
extern void vector7();
extern void vector8();
extern void vector9();
extern void vector10();
extern void vector11();
extern void vector12();
extern void vector13();
extern void vector14();
extern void vector15();
static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < ARRAY_SIZE(excnames))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}


void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
	SETGATE(idt[T_DIVIDE], 0, GD_KT, divide_error, 0);
	SETGATE(idt[T_DEBUG], 0, GD_KT, debug_error, 0);
	SETGATE(idt[T_NMI], 0, GD_KT, non_maskable_interrupt, 0);
	SETGATE(idt[T_BRKPT], 0, GD_KT, break_point, 3);
	SETGATE(idt[T_OFLOW], 0, GD_KT, over_flow, 0);
	SETGATE(idt[T_BOUND], 0, GD_KT, bound_range_exceeded, 0);
	SETGATE(idt[T_ILLOP], 0, GD_KT, invalid_opcode, 0);
	SETGATE(idt[T_DEVICE], 0, GD_KT, device_not_available, 0);
	SETGATE(idt[T_DBLFLT], 0, GD_KT, double_fault, 0);
	SETGATE(idt[T_TSS], 0, GD_KT, invalid_tss, 0);
	SETGATE(idt[T_SEGNP], 0, GD_KT, segment_not_present, 0);
	SETGATE(idt[T_STACK], 0, GD_KT, stack_fault, 0);
	SETGATE(idt[T_GPFLT], 0, GD_KT, general_protection, 3);
	SETGATE(idt[T_PGFLT], 0, GD_KT, page_fault, 0);
	SETGATE(idt[T_FPERR], 0, GD_KT, x87_fpu_floating_point_error, 0);
	SETGATE(idt[T_ALIGN], 0, GD_KT, alignment_check, 0);
	SETGATE(idt[T_MCHK], 0, GD_KT, machine_check, 0);
	SETGATE(idt[T_SIMDERR], 0, GD_KT, simd_floating_point_exception, 0);
	SETGATE(idt[T_SYSCALL], 0, GD_KT, sys_call, 3);

	SETGATE(idt[IRQ_OFFSET+0], 0, GD_KT, vector0, 0);
	SETGATE(idt[IRQ_OFFSET+1], 0, GD_KT, vector1, 0);
	SETGATE(idt[IRQ_OFFSET+2], 0, GD_KT, vector2, 0);
	SETGATE(idt[IRQ_OFFSET+3], 0, GD_KT, vector3, 0);
	SETGATE(idt[IRQ_OFFSET+4], 0, GD_KT, vector4, 0);
	SETGATE(idt[IRQ_OFFSET+5], 0, GD_KT, vector5, 0);
	SETGATE(idt[IRQ_OFFSET+6], 0, GD_KT, vector6, 0);
	SETGATE(idt[IRQ_OFFSET+7], 0, GD_KT, vector7, 0);
	SETGATE(idt[IRQ_OFFSET+8], 0, GD_KT, vector8, 0);
	SETGATE(idt[IRQ_OFFSET+9], 0, GD_KT, vector9, 0);
	SETGATE(idt[IRQ_OFFSET+10], 0, GD_KT, vector10, 0);
	SETGATE(idt[IRQ_OFFSET+11], 0, GD_KT, vector11, 0);
	SETGATE(idt[IRQ_OFFSET+12], 0, GD_KT, vector12, 0);
	SETGATE(idt[IRQ_OFFSET+13], 0, GD_KT, vector13, 0);
	SETGATE(idt[IRQ_OFFSET+14], 0, GD_KT, vector14, 0);
	SETGATE(idt[IRQ_OFFSET+15], 0, GD_KT, vector15, 0);
	// Per-CPU setup 
	trap_init_percpu();
}
// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - cpunum() * (KSTKSIZE + KSTKGAP);
	thiscpu->cpu_ts.ts_ss0 = GD_KD;
	gdt[(GD_TSS0 >> 3)+cpunum()] = SEG16(STS_T32A, (uint32_t) (&(thiscpu->cpu_ts)),
					sizeof(struct Taskstate) - 1, 0);
	gdt[(GD_TSS0 >> 3)+cpunum()].sd_s = 0;
	ltr(GD_TSS0+sizeof(struct Segdesc) * cpunum());
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.


	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}

	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	// LAB 4: Your code here.
	if(tf->tf_trapno == IRQ_OFFSET + IRQ_TIMER){
		lapic_eoi();
		sched_yield();
		return;
	}

	if(tf->tf_trapno == T_PGFLT){
		page_fault_handler(tf);
		return ;
	}
	if(tf->tf_trapno == T_BRKPT){
		monitor(tf);
		return;
	}
	if(tf->tf_trapno == T_SYSCALL){
		int r = syscall(tf->tf_regs.reg_eax, tf->tf_regs.reg_edx, 
			tf->tf_regs.reg_ecx, tf->tf_regs.reg_ebx, 
			tf->tf_regs.reg_edi, tf->tf_regs.reg_esi);
		tf->tf_regs.reg_eax = r;
		return;
	}
	if(tf->tf_trapno == IRQ_OFFSET+IRQ_KBD){
		kbd_intr();
		return;
	}
	if(tf->tf_trapno == IRQ_OFFSET+IRQ_SERIAL){
		serial_intr();
		return;
	}

	// Handle keyboard and serial interrupts.
	// LAB 5: Your code here.

	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Re-acqurie the big kernel lock if we were halted in
	// sched_yield()
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();
	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.

	assert(!(read_eflags() & FL_IF));
	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
		assert(curenv);
		lock_kernel();
		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	if((tf->tf_cs & 3) == 0)
		panic("kernel page fault\n");
	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// It is convenient for our code which returns from a page fault
	// (lib/pfentry.S) to have one word of scratch space at the top of the
	// trap-time stack; it allows us to more easily restore the eip/esp. In
	// the non-recursive case, we don't have to worry about this because
	// the top of the regular user stack is free.  In the recursive case,
	// this means we have to leave an extra word between the current top of
	// the exception stack and the new stack frame because the exception
	// stack _is_ the trap-time stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	// LAB 4: Your code here.
	if(curenv->env_pgfault_upcall){
		struct UTrapframe *utrap;
		uintptr_t utf_addr;

		if(UXSTACKTOP - PGSIZE <= tf->tf_esp && UXSTACKTOP > tf->tf_esp)
			utf_addr = tf->tf_esp - sizeof(struct UTrapframe) - 4;
		else
			utf_addr = UXSTACKTOP - sizeof(struct UTrapframe);
		user_mem_assert(curenv, (void *)utf_addr, 1, PTE_W);
		utrap = (struct UTrapframe *)utf_addr;
		utrap->utf_fault_va = fault_va;
		utrap->utf_err = tf->tf_err;
		utrap->utf_regs = tf->tf_regs;
		utrap->utf_eip = tf->tf_eip;
		utrap->utf_eflags = tf->tf_eflags;
		utrap->utf_esp = tf->tf_esp;

		curenv->env_tf.tf_eip = (uintptr_t)curenv->env_pgfault_upcall;
		curenv->env_tf.tf_esp = utf_addr;
		env_run(curenv);
	}
	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

