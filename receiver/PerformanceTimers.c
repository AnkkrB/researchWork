#include "PerformanceTimers.h"

static double ticksPerMicrosecond; // store timer parameter

// Retrieves the timer resolution and stores it globally
void InitializeTimers()
{
	LARGE_INTEGER ticksPerSecond;

	QueryPerformanceFrequency(&ticksPerSecond);
	ticksPerMicrosecond = (double) (ticksPerSecond.QuadPart/1000000.0);
}

// Initializes and returns a timer
pTimer StartTimer()
{
	LARGE_INTEGER getStartTicks;

	QueryPerformanceCounter(&getStartTicks);
	return getStartTicks;
}

// Gets the elapsed time since the start of the passed timer
int GetMicrosecondsElapsed(LARGE_INTEGER timer)
{
	LARGE_INTEGER currentTicks;

	QueryPerformanceCounter(&currentTicks);
	//return (int) ((currentTicks.QuadPart - ((LARGE_INTEGER) timer).QuadPart)/ticksPerMicrosecond);
	return (int) ((currentTicks.QuadPart - (timer).QuadPart)/ticksPerMicrosecond);
}