
#ifndef _SCRYPTPARAMS_H_
#define _SCRYPTPARAMS_H_

int pickparams(size_t, double, double, int *, uint32_t *, uint32_t *);
int checkparams(size_t, double, double, int, uint32_t, uint32_t);
int getsalt(uint8_t[32]);

#endif /* !_SCRYPTPARAMS_H_ */
