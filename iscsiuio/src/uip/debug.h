#ifndef __DEBUG_H__
#define __DEBUG_H__

#ifdef DEBUG
#define UIP_DEBUG(args...)		\
	do {				\
		fprintf(stdout, args);	\
		fflush(stdout);		\
	} while (0);
#else
#endif

#endif
