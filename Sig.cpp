#include "framework.h"
#include "Sig.h"

void (*SIG_LOG_ERROR_FUNC)(const char* fmt, ...);

#define LOG_ERROR(fmt, ...) if (SIG_LOG_ERROR_FUNC) (*SIG_LOG_ERROR_FUNC)(fmt, __VA_ARGS__);

Sig::Sig(const char* str) {
	unsigned long long accumulatedNibbles = 0;
	int nibbleCount = 0;
	const char* byteSpecificationPtr = str;
	bool nibbleUnknown[16] { false };
	while (true) {
		char currentChar = *byteSpecificationPtr;
		if (currentChar != ' ' && currentChar != '\0') {
			char currentNibble = 0;
			bool isUnknown = false;
			if (currentChar >= '0' && currentChar <= '9') {
				currentNibble = currentChar - '0';
			} else if (currentChar >= 'a' && currentChar <= 'f') {
				currentNibble = currentChar - 'a' + 10;
			} else if (currentChar >= 'A' && currentChar <= 'F') {
				currentNibble = currentChar - 'A' + 10;
			} else if (currentChar == '?') {
				isUnknown = true;
				hasWildcards = true;
			} else {
				LOG_ERROR("Wrong byte specification: %s", str)
				break;
			}
			nibbleUnknown[nibbleCount] = isUnknown;
			if ((nibbleCount % 2) == 1 && nibbleUnknown[nibbleCount] != nibbleUnknown[nibbleCount - 1]) {
				// Cannot mask only half a byte
				LOG_ERROR("Wrong byte specification: %s", str)
				break;
			}
			accumulatedNibbles = (accumulatedNibbles << 4) | currentNibble;
			++nibbleCount;
			if (nibbleCount > 16) {
				LOG_ERROR("Wrong byte specification: %s", str)
				break;
			}
		} else if (nibbleCount) {
			for (int i = 0; i < nibbleCount; i += 2) {
				sig.push_back(accumulatedNibbles & 0xff);
				mask.push_back(nibbleUnknown[i] ? '?' : 'x');
				accumulatedNibbles >>= 8;
			}
			nibbleCount = 0;
			if (currentChar == '\0') {
				break;
			}
		}
		++byteSpecificationPtr;
	}
	sig.push_back('\0');
	mask.push_back('\0');
}

#ifdef _DEBUG
const char* Sig::repr() const {
	
	if (mask.size() <= 1) return "<empty>";
	
	reprStr.clear();
	reprStr.reserve(
		(
			(mask.size() - 1)  // the last char is a null character, do not include it
			* 3  // we're going to have 2 characters per byte, + 1 space character
		)
		- 1  // omit the last space character
	);
	
	bool isFirst = true;
	const char* sigP = sig.data();
	const char* maskP = mask.data();
	while (*maskP != '\0') {
		
		if (!isFirst) {
			reprStr.push_back(' ');
		} else {
			isFirst = false;
		}
		
		BYTE sigChar = *(BYTE*)sigP;
		char maskChar = *maskP;
		if (maskChar == 'x') {
			for (int i = 0; i < 2; ++i) {
				BYTE nibble = (sigChar >> 4) & 0xf;
				char letter;
				if (nibble < 10) letter = '0' + nibble;
				else letter = 'a' + nibble - 10;
				reprStr.push_back(letter);
				sigChar <<= 4;
			}
		} else {
			reprStr.push_back('?');
			reprStr.push_back('?');
		}
		
		++sigP;
		++maskP;
	}
	
	return reprStr.c_str();
}
#endif

void Sig::replace(int offset, void* src, int size) {
	memcpy(sig.data() + offset, src, size);
	memset(mask.data() + offset, 'x', size);
}
