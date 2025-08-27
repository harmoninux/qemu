int aarch64_softmmu(int argv, char **);
int main(int argc, char **argv)
{
    /* we simply call aarch64_softmmu here, but any target linked is available */
    char *aarch64[] = {argv[0], (char *)"-M", (char *)"virt"};
    return aarch64_softmmu(3, aarch64);
}
