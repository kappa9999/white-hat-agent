/* Deterministic, inert ELF fixture used only for offline native-code-map conformance. */
static const char wha_marker_value[] = "WHA_NATIVE_CODE_MAP_MARKER";

__attribute__((noinline, used)) const char *wha_marker(void) {
    return wha_marker_value;
}

__attribute__((noinline, used)) unsigned long wha_marker_length(void) {
    const char *value = wha_marker();
    unsigned long length = 0;
    while (value[length] != '\0') {
        length++;
    }
    return length;
}

__attribute__((noreturn)) void _start(void) {
    long status = wha_marker_length() == sizeof(wha_marker_value) - 1 ? 0 : 1;
    __asm__ volatile("syscall" : : "a"(60L), "D"(status) : "rcx", "r11", "memory");
    __builtin_unreachable();
}
