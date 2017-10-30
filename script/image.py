#!/bin/env python
import sys
import struct
import base64

import headers

if __name__ == "__main__":
	file = sys.argv[1]
	f = open(file,"rb")
	data = bytearray( f.read() )
	f.close()
	packets = data.split("------packet break--------\n")

	_data = base64.b64decode(buffer(packets[0]))[10:]


	print repr( _data[0:16])
	header,_data = headers.get_header( _data )
	
	print repr(header)

	while len(_data) > 0:
		header,_data = headers.get_header( _data )
		print "*************"
		print repr(header)
		print "*************"
	
