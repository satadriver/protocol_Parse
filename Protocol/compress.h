
#ifndef COMP_UNCOMP_H_H_H
#define COMP_UNCOMP_H_H_H

#include "include\\zlib.h"
#include "include\\zconf.h"



class Compress {
public:

	static int GzipDecode(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata);
	static int GzipEncode(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata);

	static int zcompress(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata);
	static int Compress::zdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata);

	static int Compress::gzcompress(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata);
	static int Compress::gzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata);
	static int Compress::httpgzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata);
};



#endif