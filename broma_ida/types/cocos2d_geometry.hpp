#ifndef COCOS2D_GEOMETRY
#define COCOS2D_GEOMETRY

typedef unsigned char GLubyte;

namespace cocos2d
{
	// CCGeometry
	class CCPoint
	{
	public:
		float x;
		float y;

		CCPoint()
			: x(.0f), y(.0f)
		{}

		CCPoint(const CCPoint& p)
			: x(p.x), y(p.y)
		{};

		CCPoint(float x, float y)
			: x(x), y(y)
		{};
	};

	class CCSize
	{
	public:
		float width;
		float height;

		inline CCSize() : width(0), height(0) {}
		inline CCSize(float width, float height) : width(width), height(height) {}
	};

	class CCRect
	{
	public:
		CCPoint origin;
		CCSize  size;
	};

	#define CCPointMake(x, y) cocos2d::CCPoint((float)(x), (float)(y))
	#define CCSizeMake(width, height) cocos2d::CCSize((float)(width), (float)(height))
	#define CCRectMake(x, y, width, height) cocos2d::CCRect((float)(x), (float)(y), (float)(width), (float)(height))

	#define CCPointZero CCPointMake(0,0)
	#define CCSizeZero CCSizeMake(0,0)
	#define CCRectZero CCRectMake(0,0,0,0)
}

#endif
