void * __cdecl memcpy (
        void * dst,
        const void * src,
        unsigned int count
        )
{
        void * ret = dst;

        /*
         * copy from lower addresses to higher addresses
         */
        while (count--) {
                *(char *)dst = *(char *)src;
                dst = (char *)dst + 1;
                src = (char *)src + 1;
        }

        return(ret);
}
