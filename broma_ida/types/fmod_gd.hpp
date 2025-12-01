#ifndef PAD
#define STR_CONCAT_WRAPPER(a, b) a ## b
#define STR_CONCAT(a, b) STR_CONCAT_WRAPPER(a, b)
#define PAD(size) unsigned char STR_CONCAT(__pad, __LINE__)[size]
#endif

namespace FMOD
{
	class FMODSoundTween
	{
	private:
#ifdef BROMAIDA_PLATFORM_WINDOWS
		PAD(0x28);
#endif
	};
}
