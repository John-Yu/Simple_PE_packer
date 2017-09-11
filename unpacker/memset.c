void * __cdecl memset (
        void *dst,
        int val,
        unsigned int count
        )
{
        void *start = dst;

        while (count--) {
                *(char *)dst = (char)val;
                dst = (char *)dst + 1;
        }

        return(start);
}
