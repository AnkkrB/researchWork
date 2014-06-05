#ifndef PERFORMANCETIMERS_H
#define PERFORMANCETIMERS_H

#ifndef _INC_WINDOWS
#include <windows.h>
#endif /* _INC_WINDOWS */

typedef LARGE_INTEGER pTimer;

// call this prior to using any timers
void InitializeTimers();

// returns a timer that can be passed to GetMicrosecondsElapsed
pTimer StartTimer();

// returns the integer number of microseconds since the timer was started with StartTimer
int GetMicrosecondsElapsed(pTimer timer);

#endif