#!/usr/local/bin/python

import json, os, re, socket, struct, sys
import base64
from hexdump import hexdump

from rs import reedsolomon
#from image import get_next_header

crc_table = [ 0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
              0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
              0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
              0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
              0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
              0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
              0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
              0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
              0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
              0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
              0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
              0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
              0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
              0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
              0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
              0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
              0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
              0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
              0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
              0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
              0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
              0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
              0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
              0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
              0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
              0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
              0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
              0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
              0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
              0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
              0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
              0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0 ]

def crc( data ):
  crc = 0xffff
  for x in data:
    crc = 0xffff & ( crc << 8 ) ^ crc_table[ ( crc >> 8 ) ^ x ]
  return crc

class LRIT:

  frame_sync = b'\x1a\xcf\xfc\x1d'

  def __init__( self, host, port=4001, file=None ):
    if file is not None:
      self.mode = 'file'
      self.fd = open( file, 'rb' )
    else:
      self.mode = 'sock'
      self.host = host
      self.port = port
      self.connect()
      #self.sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
      #self.sock.connect( ( host, port ) )
    self.buffer = None
    self.nodata_counter = 0

  def __iter__( self ):
    return self

  def connect( self ):
      self.nodata_counter = 0
      self.sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
      self.sock.connect( ( self.host, self.port ) )
      self.sock.setblocking(0)


  def next( self ):
    if self.buffer is None:                    # Initial sync
      while True:
        chunk = self.read_chunk( 1024 )
        i = chunk.find( LRIT.frame_sync )
        if i != -1:
          self.buffer = chunk[i+4:]
          break

    while True:
      i = self.sync_frame()
      if i != -1:
        frame = LRIT.frame( LRIT.frame_sync + self.buffer[:i] )
        self.buffer = self.buffer[i+4:]
        return frame
      self.buffer += self.read_chunk( 1024 )

  def sync_frame( self ):
    i = self.buffer.find( LRIT.frame_sync )
    if i == -1:
      return -1

    # If LRIT frame_sync found early, keep looking until we have at least 1020
    # bytes of data after the initial frame_sync to pass to Reed-Solomon, or
    # run out of buffer

    while i < 1020:
      inc = self.buffer.find( LRIT.frame_sync, i + 4 )
      if inc == -1:
        return -1
      if cfg( 'verbose' ):
        print color( 'cyan', "i = %d, inc = %d\n%s" % ( i, inc,
                             hexdump( str( self.buffer ), result='return' ) ) )
      i = inc
    return i

  def read_chunk( self, size ):
    chunk = ""
    if self.mode == 'file': chunk = self.fd.read( size )
    else:
      import select
      #check that the socket has data
      ins,outs,errors = select.select( [self.sock,],[],[self.sock],.1)
      if len( ins ) == 1:
        try:
	  chunk = self.sock.recv( size )
	  self.nodata_counter = self.nodata_counter - 1
	  if self.nodata_counter < 0:
	  	self.nodata_counter = 0
	except socket.error, err:
	  print color('red', "Socket Failed, reconnecting: %s: %s"% (repr(err),str(err)) )
	  self.sock.close()
	  self.connect()
      elif len(errors) > 0:
        print color('red', "Socket Error has Occured")
      else:
        self.nodata_counter = self.nodata_counter + 1
        print color('yellow', "No data available")
	if self.nodata_counter > 5:
		print color('yellow', " Restarting Connection" )
		self.sock.close()
		self.connect()
	
    return bytearray( chunk )

  #############################################################################

  class frame:
    def __init__( self, buffer ):
      size = len( buffer )
      if size != 1024:
        print color( 'red', "CADU frame is %d bytes instead of 1024\n%s" %
                     ( size, hexdump( str( buffer ), result='return' ) ) )
      buffer = bytearray( buffer )
      if rs.decode( buffer ) == False:
        print color( 'red', "%d errors/frame\n%d uncorrectable errors/frame" %
                     ( rs.num_errors_per_frame, rs.uncor_errs_per_frame ) )

      buffer = str( buffer[:-128] )   # Drop the Reed-Solomon codes

      # Decode VCDU primary header

      ( vcdu1, vcdu2 ) = struct.unpack( "!HL", buffer[4:10] )
      self.version    = ( vcdu1 & 0xc000 ) >> 14
      self.spacecraft = ( vcdu1 & 0x3fc0 ) >> 6
      self.channel    =   vcdu1 & 0x003f

      self.counter    = ( vcdu2 & 0xffffff00 ) >> 8
      self.replay     = ( vcdu2 & 0x00000080 ) >> 7
      self.spare      =   vcdu2 & 0x0000007f

      # Decode M_PDU header

      self.first_header_ptr = struct.unpack( '!H', buffer[10:12] )[0] & 0x07ff
      self.packet_zone = buffer[12:]

      if( cfg( 'verbose', 'tuned_frame' ) and tuning( self.channel ) ):
        msg = """CADU Frame:
 Version: %3d  Channel: %8d     FHP: %8d (0x%x)
   Craft: %3d  Counter: %8d  Replay: %8d""" % ( self.version, self.channel,
          self.first_header_ptr, self.first_header_ptr, self.spacecraft,
          self.counter, self.replay )
        print color( 'green', msg )
        print color( 'green', hexdump( str( buffer ), result='return' ) )
      elif tuning( self.channel ):
        print color( 'green', "Ch %d frame" % ( self.channel ) )
      else:
        print color( 'white', "Ch %d frame" % ( self.channel ) )

  #############################################################################

  class transport_file:
    def __init__( self, channel, packet ):
      self.data = bytearray()
      self._packets = [] # individual packets for reconstruction
      self.channel = channel
      self.length = None
      # compression flag check here
      self.decode_packet( packet )
      self.image_info = [] # if this is an image, we need to stor at least the rice/other compression header
      self.is_image = False # if image, alter the way we do things a bit
    def decode_packet( self, packet ):
      if len( self.data ) == 0 and not packet.seq_first:
        print color( 'blue', 'Ch %d, APID %d: No first packet yet' %
                             ( self.channel, packet.apid ) )
        return

      if packet.seq_first:
        # see how many headers we can get, set an additional variable if we don't have full headers yet
	# if we find the rice header, set it aside. 
	# if there is data after the headers, decompress
	#   (and hope there isn't another rediculous boundary/encapsulation layer involved.)
        pass
      # add compression checks here

      #if isImage
         #decompress packet data first
      #else:
      self.data += packet.data
      self._packets.append( packet.data )
      

      if self.length is None and len( packet.data ) >= 10:
        ( self.file_counter, self.length ) = struct.unpack( "!HQ",
                                                            buffer(packet.data[0:10]) )
      if packet.seq_last and len( self.data ) >= 26:
        ( header_type, record_len, file_type, header_len,
          bitlength ) = struct.unpack( '!BHBLQ', buffer(self.data[10:26]) )
        if header_type != 0:
          print color( 'yellow', "Primary Header Record type is %d, not 0!" %
                                 ( header_type ) )
        if record_len != 16:
          print color( 'yellow', "Primary Header Record length is %d, not 16!"
                                 % ( record_len ) )
        self.record_len = record_len
        self.file_type = file_type
        self.header_len = header_len
        print "Channel %d, file Type %d" % ( self.channel, file_type )
        print "Secondary Headers: %d bytes" % ( header_len - record_len )
        #hexdump( str( self.data[26:26 + header_len - record_len] ) )
        print "Output file: %d bytes" % ( len( self.data ) -
                                          26 - header_len + record_len )
        #hexdump( str( self.data[26 + header_len - record_len:] ) )
        if cfg( 'channel', str( self.channel ), 'files', str( file_type ) ):
          dir = cfg( 'channel', str( self.channel ), 'files',
                     str( file_type ), 'directory' )
          if dir:
            if dir[0] != '/': dir = cfg( 'base_directory' ) + "/" + dir
            self.write_file( dir )
        elif cfg( 'channel', str( self.channel ), 'file_by_type' ):
          dir = "%s/%s/%s" % ( cfg( 'base_directory' ), str( self.channel ),
                               str( file_type ) )
          self.write_file( dir )

        self.data = bytearray()
	self.packets = []
        self.length = None
        self.file_type = None

    def write_file( self, dir ):
      if not os.path.exists( dir ): os.makedirs( dir )
      timestamp = ""
      if self.channel == 0: #this is emwin so lets prefix with time to keep the packets in order
        import datetime
	dt = datetime.datetime.now()-datetime.datetime(1970,1,1)
      	timestamp = str(int((dt.days * 24 * 60 * 60 + dt.seconds) * 1000 + dt.microseconds / 1000.0))
      filename = "%s/%s%d" % ( dir, timestamp,self.file_counter )
      fd = open( filename + ".head", "w" )
      fd.write( buffer( self.data[10:26 + self.header_len - self.record_len] ) )
      fd.close()
      #fd = open( filename, "w" )
      #fd.write( buffer( self.data[26 + self.header_len - self.record_len:] ) )
      #fd.close()
      i = 0
      fd = open( filename +".packets", "w" )
      for p in self._packets:
        fd.write( base64.b64encode(buffer(p)) +"\n")
	fd.write( "------packet break--------\n")
	i = i+1
      fd.close()
         
  #############################################################################

  class packet:
    def __init__( self, data ):
      self.version = None
      data_len = len( data )
      if data_len < 6:                   # too short to be complete, abort
        return
      ( id, seq, length ) = struct.unpack( "!HHH", buffer(data[0:6]) )
      length += 1                        # length = octets in data *minus one*
      self.version        = ( id & 0xe000 ) >> 13
      self.type           = ( id & 0x1000 ) >> 12
      self.secondary_flag = ( id & 0x0800 ) >> 11
      self.apid           =   id & 0x07ff
      self.seq_last       = ( seq & 0x8000 ) >> 15
      self.seq_first      = ( seq & 0x4000 ) >> 14
      self.seq_ctr        =   seq & 0x3fff
      self.length         =   length
      if length + 6 > data_len:            # incomplete packet, abort
        self.version = None
        return
      self.data = data[6:length+4]         # trim off header and CRC
      self.crc = struct.unpack( "!H", buffer(data[length+4:length+6]) )[0]
      computed_crc = crc( self.data )
      msg = """CP_PDU Packet:
   Version: %4d    APID: %5d  Counter: %5d
      Type: %4d  First?: %5d   Length: %5d (0x%x)
 2ary Flag: %4d   Last?  %5d      CRC: %4x v %4x""" % ( self.version,
        self.apid, self.seq_ctr, self.type, self.seq_first, self.length,
        self.length, self.secondary_flag, self.seq_last, self.crc,
        computed_crc )
      if self.apid != 2047 and self.crc != computed_crc:
        print color( 'red', msg )
        print color( 'yellow',
                     hexdump( str( data[0:length+6] ), result='return' ) )
      elif cfg( 'verbose', 'tuned_packet' ):
        print color( 'blue', msg )

  #############################################################################

  class channel:
    def __init__( self, channel ):
      self.buffer = bytearray()
      self.channel = channel
      self.apids = {}

    def add_frame( self, data, first ):
      if not first and len( self.buffer ) == 0:  # Discard any first partial
        return                                   # packet: we can't use it
      self.buffer += data
      pack = LRIT.packet( self.buffer )
      while pack.version is not None:
        apid = pack.apid
        if apid == 2047:
          pass
        elif apid in self.apids:
          self.apids[apid].decode_packet( pack )
        else:
          self.apids[apid] = LRIT.transport_file( self.channel, pack )
        self.buffer = self.buffer[pack.length+6:]
        pack = LRIT.packet( self.buffer )

###############################################################################

color_map = {   'black': '\33[40m\33[97m',
                 'blue': '\33[44m\33[97m',
                 'cyan': '\33[46m\33[97m',
                'green': '\33[42m\33[97m',
              'magenta': '\33[45m\33[97m',
                  'red': '\33[41m\33[97m',
                'white': '\33[47m\33[30m',
               'yellow': '\33[43m\33[30m' }

def color( color, text ):
  return '%s%s\33[39m\33[49m' % ( color_map[color], text )

def tuning( channel ):
  if cfg( 'channel', str( channel ) ):
    return True
  return False

# Iteratively burrow down into the configuration looking for a value.
# Return it if it's there, otherwise return False

def cfg( *indices ):
  cf = conf
  for index in indices:
    if index not in cf:
      return False
    cf = cf[index]
  return cf

def parseArgs():
  import optparse
  parser=optparse.OptionParser()
  parser.add_option('-c', '--config', dest='config', default="/usr/apps/lrit_files/script/config.json", help="JSON config file", metavar="CONFIGFILE")
  parser.add_option('-f', '--file', dest='filename', default=None, help="File of data to test data from instead of connecting live data.", metavar="DATAFILE" )

  return parser.parse_args()[0] # note, this will need to be changed if anyone wants to add non-named arguments

if __name__ == '__main__':
  args = parseArgs()
  config = args.config
  conf = json.loads( ''.join( open( config ).readlines() ) )
  filename = args.filename
  if filename is not None:
    print "Reading satellite data from file: ", filename
  channel = []
  for chan in range( 64 ):
    channel.append( LRIT.channel( chan ) )

  rs = reedsolomon( 8, 16, 112, 11, 0, 4, 0, 1 )

  for frame in LRIT( cfg("address"), port=cfg("port"), file=filename ):
    if not tuning( frame.channel ):
      continue
    chan = channel[frame.channel]
    fhp = frame.first_header_ptr
    if fhp == 2047:
      chan.add_frame( frame.packet_zone, first=False )
      continue
    elif fhp != 0:
      chan.add_frame( frame.packet_zone[:fhp], first=False )
    chan.add_frame( frame.packet_zone[fhp:], first=True  )
