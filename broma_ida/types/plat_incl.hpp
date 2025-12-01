#ifdef BROMAIDA_PLATFORM_WINDOWS
struct XINPUT_GAMEPAD
{
    unsigned short wButtons;
    unsigned char bLeftTrigger;
    unsigned char bRightTrigger;
    short sThumbLX;
    short sThumbLY;
    short sThumbRX;
    short sThumbRY;
};

struct XINPUT_STATE
{
    unsigned long dwPacketNumber;
    XINPUT_GAMEPAD Gamepad;
};

using UINT = unsigned int;
using WPARAM = unsigned long long;
using LPARAM = long long;
using LPCWSTR = const wchar_t*;

using HWND = void*;

using GLFWmonitor = struct GLFWmonitor;
using GLFWwindow = struct GLFWwindow;
#endif // BROMAIDA_PLATFORM_WINDOWS
