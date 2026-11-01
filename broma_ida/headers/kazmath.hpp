/*
Copyright (c) 2008, Luke Benstead.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// screw you luke benstead, what is your problem

typedef float kmScalar;

typedef struct kmVec2 {
    kmScalar x;
    kmScalar y;
} kmVec2;

typedef struct kmVec3 {
    kmScalar x;
    kmScalar y;
    kmScalar z;
} kmVec3;

typedef struct kmVec4 {
    kmScalar x;
    kmScalar y;
    kmScalar z;
    kmScalar w;
} kmVec4;

typedef struct kmMat3 {
    kmScalar mat[9];
} kmMat3;

typedef struct kmMat4 {
    kmScalar mat[16];
} kmMat4;

typedef struct kmQuaternion {
    kmScalar x;
    kmScalar y;
    kmScalar z;
    kmScalar w;
} kmQuaternion;

typedef struct kmPlane {
    kmScalar     a, b, c, d;
} kmPlane;

typedef enum POINT_CLASSIFICATION {
    POINT_INFRONT_OF_PLANE = 0,
    POINT_BEHIND_PLANE,
    POINT_ON_PLANE,
} POINT_CLASSIFICATION;

typedef struct kmAABB {
    kmVec3 min; /** The max corner of the box */
    kmVec3 max; /** The min corner of the box */
} kmAABB;

typedef struct kmRay2 {
    kmVec2 start;
    kmVec2 dir;
} kmRay2;
