/* Deterministic, inert ELF fixture used only for offline adapter conformance. */
__attribute__((noreturn)) void _start(void) {
    __asm__ volatile("mov $60, %rax\n\txor %rdi, %rdi\n\tsyscall");
    __builtin_unreachable();
}
