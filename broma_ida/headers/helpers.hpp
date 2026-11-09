#ifndef PAD
#define STR_CONCAT_WRAPPER(a, b) a ## b
#define STR_CONCAT(a, b) STR_CONCAT_WRAPPER(a, b)
#define PAD(size) unsigned char STR_CONCAT(__pad, __LINE__)[size]
#endif

// these SeedValue classes were originally under the 'geode::' namespace
// but we strip that namespace for now until a more permanent solution like an sdk parser comes up

class SeedValueSR
{
public:
	int seed;
	int random;
};

class SeedValueRS
{
public:
	int random;
	int seed;
};


class SeedValueVRS
{
public:
	int value;
	int random;
	int seed;
};

class SeedValueVSR
{
public:
	int value;
	int seed;
	int random;
};

class SeedValueRVS
{
public:
	int random;
	int value;
	int seed;
};

class SeedValueRSV
{
public:
	int random;
	int seed;
	int value;
};

class SeedValueSVR
{
public:
	int seed;
	int value;
	int random;
};

class SeedValueSRV
{
public:
	int seed;
	int random;
	int value;
};
