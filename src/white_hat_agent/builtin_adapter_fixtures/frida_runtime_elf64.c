/* Reproduce with:
 * gcc -std=c11 -Os -fno-ident -fno-stack-protector -fno-asynchronous-unwind-tables \
 *   -Wl,--build-id=none -Wl,--export-dynamic -Wl,-z,noexecstack -no-pie \
 *   -o frida_runtime_fixture.elf frida_runtime_elf64.c
 */
__attribute__((noinline, visibility("default")))
int wha_runtime_marker(int value) {
    return value + 7;
}

int main(void) {
    return wha_runtime_marker(35) == 42 ? 0 : 1;
}
