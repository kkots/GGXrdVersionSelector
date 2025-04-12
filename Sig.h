#pragma once
#include <vector>
#include <string>

extern void (*SIG_LOG_ERROR_FUNC)(const char* fmt, ...);

class Sig {
public:
	// str is a byte specification of the format "00 8f 1e ??". ?? means unknown byte.
	// Converts a "00 8f 1e ??" string into two vectors:
	// sig vector will contain bytes '00 8f 1e' for the first 3 bytes and 00 for every ?? byte.
	// sig vector will be terminated with an extra 0 byte.
	// mask vector will contain an 'x' character for every non-?? byte and a '?' character for every ?? byte.
	// mask vector will be terminated with an extra 0 byte.
	Sig() = default;
	Sig(const Sig& sig) = default;
	Sig(Sig&& sig) = default;
	Sig& operator=(const Sig& sig) = default;
	Sig& operator=(Sig&& sig) = default;
	explicit Sig(const char* str);
	std::vector<char> sig;
	std::vector<char> mask;
	bool hasWildcards = false;
	void replace(int offset, void* src, int size);
	#ifdef _DEBUG
	mutable std::string reprStr;
	const char* repr() const;
	#endif
};
