import math

class reedsolomon:

  gf256= [ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
	   0x87, 0x89, 0x95, 0xAD, 0xDD, 0x3D, 0x7A, 0xF4,
	   0x6F, 0xDE, 0x3B, 0x76, 0xEC, 0x5F, 0xBE, 0xFB,
	   0x71, 0xE2, 0x43, 0x86, 0x8B, 0x91, 0xA5, 0xCD,
	   0x1D, 0x3A, 0x74, 0xE8, 0x57, 0xAE, 0xDB, 0x31,
	   0x62, 0xC4, 0x0F, 0x1E, 0x3C, 0x78, 0xF0, 0x67,
	   0xCE, 0x1B, 0x36, 0x6C, 0xD8, 0x37, 0x6E, 0xDC,
	   0x3F, 0x7E, 0xFC, 0x7F, 0xFE, 0x7B, 0xF6, 0x6B,
	   0xD6, 0x2B, 0x56, 0xAC, 0xDF, 0x39, 0x72, 0xE4,
	   0x4F, 0x9E, 0xBB, 0xF1, 0x65, 0xCA, 0x13, 0x26,
	   0x4C, 0x98, 0xB7, 0xE9, 0x55, 0xAA, 0xD3, 0x21,
	   0x42, 0x84, 0x8F, 0x99, 0xB5, 0xED, 0x5D, 0xBA,
	   0xF3, 0x61, 0xC2, 0x03, 0x06, 0x0C, 0x18, 0x30,
	   0x60, 0xC0, 0x07, 0x0E, 0x1C, 0x38, 0x70, 0xE0,
	   0x47, 0x8E, 0x9B, 0xB1, 0xE5, 0x4D, 0x9A, 0xB3,
	   0xE1, 0x45, 0x8A, 0x93, 0xA1, 0xC5, 0x0D, 0x1A,
	   0x34, 0x68, 0xD0, 0x27, 0x4E, 0x9C, 0xBF, 0xF9,
	   0x75, 0xEA, 0x53, 0xA6, 0xCB, 0x11, 0x22, 0x44,
	   0x88, 0x97, 0xA9, 0xD5, 0x2D, 0x5A, 0xB4, 0xEF,
	   0x59, 0xB2, 0xE3, 0x41, 0x82, 0x83, 0x81, 0x85,
	   0x8D, 0x9D, 0xBD, 0xFD, 0x7D, 0xFA, 0x73, 0xE6,
	   0x4B, 0x96, 0xAB, 0xD1, 0x25, 0x4A, 0x94, 0xAF,
	   0xD9, 0x35, 0x6A, 0xD4, 0x2F, 0x5E, 0xBC, 0xFF,
	   0x79, 0xF2, 0x63, 0xC6, 0x0B, 0x16, 0x2C, 0x58,
	   0xB0, 0xE7, 0x49, 0x92, 0xA3, 0xC1, 0x05, 0x0A,
	   0x14, 0x28, 0x50, 0xA0, 0xC7, 0x09, 0x12, 0x24,
	   0x48, 0x90, 0xA7, 0xC9, 0x15, 0x2A, 0x54, 0xA8,
	   0xD7, 0x29, 0x52, 0xA4, 0xCF, 0x19, 0x32, 0x64,
	   0xC8, 0x17, 0x2E, 0x5C, 0xB8, 0xF7, 0x69, 0xD2,
	   0x23, 0x46, 0x8C, 0x9F, 0xB9, 0xF5, 0x6D, 0xDA,
	   0x33, 0x66, 0xCC, 0x1F, 0x3E, 0x7C, 0xF8, 0x77,
	   0xEE, 0x5B, 0xB6, 0xEB, 0x51, 0xA2, 0xC3 ]

  gf256d = [ 0x7B, 0xAF, 0x99, 0xFA, 0x86, 0xEC, 0xEF, 0x8D,
	     0xC0, 0x0C, 0xE9, 0x79, 0xFC, 0x72, 0xD0, 0x91,
	     0xB4, 0x28, 0x44, 0xB3, 0xED, 0xDE, 0x2B, 0x26,
	     0xFE, 0x21, 0x3B, 0xBB, 0xA3, 0x70, 0x83, 0x7A,
	     0x9E, 0x3F, 0x1C, 0x74, 0x24, 0xAD, 0xCA, 0x11,
	     0xAC, 0xFB, 0xB7, 0x4A, 0x09, 0x7F, 0x08, 0x4E,
	     0xAE, 0xA8, 0x5C, 0x60, 0x1E, 0x27, 0xCF, 0x87,
	     0xDD, 0x49, 0x6B, 0x32, 0xC4, 0xAB, 0x3E, 0x2D,
	     0xD2, 0xC2, 0x5F, 0x02, 0x53, 0xEB, 0x2A, 0x17,
	     0x58, 0xC7, 0xC9, 0x73, 0xE1, 0x37, 0x52, 0xDA,
	     0x8C, 0xF1, 0xAA, 0x0F, 0x8B, 0x34, 0x30, 0x97,
	     0x40, 0x14, 0x3A, 0x8A, 0x05, 0x96, 0x71, 0xB2,
	     0xDC, 0x78, 0xCD, 0xD4, 0x36, 0x63, 0x7C, 0x6A,
	     0x03, 0x62, 0x4D, 0xCC, 0xE5, 0x90, 0x85, 0x8E,
	     0xA2, 0x41, 0x25, 0x9C, 0x6C, 0xF7, 0x5E, 0x33,
	     0xF5, 0x0D, 0xD8, 0xDF, 0x1A, 0x80, 0x18, 0xD3,
	     0xF3, 0xF9, 0xE4, 0xA1, 0x23, 0x68, 0x50, 0x89,
	     0x67, 0xDB, 0xBD, 0x57, 0x4C, 0xFD, 0x43, 0x76,
	     0x77, 0x46, 0xE0, 0x06, 0xF4, 0x3C, 0x7E, 0x39,
	     0xE8, 0x48, 0x5A, 0x94, 0x22, 0x59, 0xF6, 0x6F,
	     0x95, 0x13, 0xFF, 0x10, 0x9D, 0x5D, 0x51, 0xB8,
	     0xC1, 0x3D, 0x4F, 0x9F, 0x0E, 0xBA, 0x92, 0xD6,
	     0x65, 0x88, 0x56, 0x7D, 0x5B, 0xA5, 0x84, 0xBF,
	     0x04, 0xA7, 0xD7, 0x54, 0x2E, 0xB0, 0x8F, 0x93,
	     0xE7, 0xC3, 0x6E, 0xA4, 0xB5, 0x19, 0xE2, 0x55,
	     0x1F, 0x16, 0x69, 0x61, 0x2F, 0x81, 0x29, 0x75,
	     0x15, 0x0B, 0x2C, 0xE3, 0x64, 0xB9, 0xF0, 0x9B,
	     0xA9, 0x6D, 0xC6, 0xF8, 0xD5, 0x07, 0xC5, 0x9A,
	     0x98, 0xCB, 0x20, 0x0A, 0x1D, 0x45, 0x82, 0x4B,
	     0x38, 0xD9, 0xEE, 0xBC, 0x66, 0xEA, 0x1B, 0xB1,
	     0xBE, 0x35, 0x01, 0x31, 0xA6, 0xE6, 0xF2, 0xC8,
	     0x42, 0x47, 0xD1, 0xA0, 0x12, 0xCE, 0xB6 ]

  def __init__( self, bits_per_symbol, correctable_errors, mo, poa,
                virtual_fill, interleave, frame_sync_length, mode ):

    self.m = bits_per_symbol
    self.n = 2 ** bits_per_symbol - 1
    self.t = correctable_errors
    self.d = 2 * correctable_errors
    self.k = ( self.n - 2 * correctable_errors ) - virtual_fill
    self.Mo = mo
    self.poa = poa
    self.vf = virtual_fill
    self.I = interleave
    self.mode = mode
    self.modulus = self.n
    self.fs_length = frame_sync_length
    self.frame_length = ( frame_sync_length +
			  ( self.n - self.d - self.vf ) * self.I +
			  self.d * self.I )
    self.syn_loop_max = ( self.frame_length - frame_sync_length )

    self.num_errors_per_frame = 0
    self.uncor_errs_per_frame = 0

    self.num_errors_per_interleave = bytearray( interleave )

    self.s                = bytearray( self.d )
    self.sigma            = bytearray( self.d )
    self.error_magnitudes = bytearray( self.t )
    self.error_locations  = bytearray( self.t )
    self.D                = bytearray( self.d )
    self.tmp_sigma        = bytearray( self.d )
    self.Z                = bytearray( self.t + 1 )

    # determine max number of repititions for the antilog table

    m1 = self.n + 1 + self.poa * ( self.Mo + self.n )
    m2 = self.n + 1 + self.poa * self.n * 2 * self.t
    max_antilog_repetitions = max( m1, m2 )
    max_antilog_repetitions = max_antilog_repetitions / self.n + 1

    # allocate memory to hold Galois Field tables, the base table becomes the
    # antilog table, and is repeated XXX number of times to eliminate the use of
    # the mod function, since this is a time consuming operation, the antilog
    # table will always be of length = 2^m

    self.log_ptr     = bytearray( self.n + 1 )
    self.antilog_ptr = bytearray( max_antilog_repetitions * self.n )

    # load table

    if mode == 1 and self.m == 8:
      self.antilog_ptr = bytearray( reedsolomon.gf256d )
    if mode == 0 and self.m == 8:
      self.antilog_ptr = bytearray( reedsolomon.gf256  )

    # repeat GF antilog table maxAntilogReptitions times

    self.antilog_ptr = self.antilog_ptr * max_antilog_repetitions

    # load GF log table
    self.log_ptr[0] = 0
    for i in range( self.n ):
      self.log_ptr[self.antilog_ptr[i]] = i

  #############################################################################
  # define overloaded operator functions

  def correctable_errors_in_frame( self ):
    return self.num_errors_per_frame

  def uncorrectable_errors_in_frame( self ):
    return self.uncor_errs_per_frame

  # this returns the number of errors per interleave where you must pass an
  # array of length Interleave to receive the results

  def correctable_errors_per_interleave( self, errors_per_interleave ):
    for i in range( self.I ):
      errors_per_interleave[i] = self.num_errors_per_interleave[i]


  #############################################################################
  # Define member operations functions
  #############################################################################

  # decode the data frame
  # This function passes each interleaved code block to the core decoder.  It
  # also maintains statistics.
  # returns true if no errors, false if correctable or uncorrectable errors

  def decode( self, rs_data_frame ):
    num_errors = 0

    # the start of data is self.fs_length bytes from the beginning of the frame
    # because the frame sync pattern takes up the first self.fs_length bytes

    start_of_data = rs_data_frame[self.fs_length:]

    # decode and correct each code word, the value of i specifies
    # which level in the interleaved code block to decode

    self.uncor_errs_per_frame = 0
    self.num_errors_per_frame = 0

    for i in range( self.I ):
      num_errors = self.rs_decode( start_of_data, i )
      if num_errors > 0:
        self.num_errors_per_frame += num_errors
        self.num_errors_per_interleave[i] = num_errors
      elif num_errors < 0:
        self.uncor_errs_per_frame += 1
        self.num_errors_per_interleave[i] = 0

    if self.num_errors_per_frame > 0 or self.uncor_errs_per_frame > 0:
      return False
    return True

  def rs_decode( self, rs_data, interleave ):
    num_errors = 0
    degree_of_sigma = 0

    self.s                = bytearray( self.d )
    self.sigma            = bytearray( self.d )
    self.error_locations  = bytearray( self.t )
    self.error_magnitudes = bytearray( self.t )

    if self.rsd_calc_syndrome( rs_data, interleave ) != 0:
      degree_of_sigma = self.rsd_calc_elp_coef()
      if degree_of_sigma == -1: return -2

      num_errors = self.rsd_calc_error_locations( degree_of_sigma )
      if num_errors == -1: return -3

      if self.rsd_calc_error_magnitudes( num_errors ) == -1:
            return -4

      self.rsd_correct_symbols( rs_data, interleave, num_errors )

    return num_errors

  def rsd_calc_syndrome( self, r, interleave ):
    check_sum = 0

    for i in xrange( self.d ):
      term = self.poa * ( self.Mo + i )
      for j in xrange( interleave, self.syn_loop_max, self.I ):
        if self.s[i] != 0:
          self.s[i] = self.antilog_ptr[self.log_ptr[self.s[i]] + term] ^ r[j]
        else:
          self.s[i] = r[j]

      check_sum += self.s[i]

    return check_sum

  def rsd_calc_elp_coef( self ):
    self.D = bytearray( self.d )
    self.tmp_sigma = bytearray( self.d )
    L = tmpL = 0
    k = -1
    self.sigma[0] = self.antilog_ptr[0]
    self.D[1] = self.antilog_ptr[0]

    # for each syndrome symbol...

    for n in xrange( self.d ):
      d = 0
      for i in xrange( L ):
        if self.sigma[i] != 0 and self.s[n-i] != 0:
          d = d ^ self.antilog_ptr[(self.log_ptr[self.sigma[i]] +
                    self.log_ptr[self.s[n-i]])]

        # if there is a discrepancy...
        if d != 0:
          for i in xrange( self.d ):
            if self.D[i] != 0:
              self.tmp_sigma[i] = ( self.sigma[i] ^
                self.antilog_ptr[(self.log_ptr[d] + self.log_ptr[self.D[i]])] )
            else:
              self.tmp_sigma[i] = self.sigma[i]

            if L < (n - k):
              tmpL = n - k
              k = n - L

              power_of_alpha = self.n - self.log_ptr[d]
              for i in xrange( self.d ):
                if power_of_alpha != 0 and self.sigma[i] != 0:
                  self.D[i] = self.antilog_ptr[self.log_ptr[self.sigma[i]] +
                                           power_of_alpha]
                else:
                  self.D[i] = 0

            L = tmpL

            self.sigma = list( self.tmp_sigma )

        for i in xrange( self.d - 1, 1, -1 ):
          self.D[i] = self.D[i-1]
        self.D[0] = 0x00

    return L

  def rsd_calc_error_locations( self, degree_of_sigma ):
    num_errors = 0

    for j in xrange( self.n ):
      sum = self.sigma[0]
      for i in xrange( degree_of_sigma ):
        power_of_alpha = i * j * self.poa
        if power_of_alpha !=0 and self.sigma[i] != 0:
          sum = sum ^ self.antilog_ptr[(self.log_ptr[self.sigma[i]] +
                                        power_of_alpha)]
      if sum == 0:
        if num_errors == self.t:
          return -1
        else:
          self.error_locations[num_errors] = self.n - j
          num_errors += 1

    if num_errors != degree_of_sigma:
      return -1

    return num_errors

  def rsd_calc_error_magnitudes( self, num_errors ):

    dtmp = math.floor((self.t - 1.0)/2.0)
    elp_max = int( dtmp )

    self.Z = bytearray( self.t + 1 )

    self.Z[0] = self.antilog_ptr[0]
    for i in xrange( num_errors ):
      self.Z[i] = self.s[i-1] ^ self.sigma[i]
      for j in xrange( i ):
        if self.sigma[j] != 0 and self.s[(i-j)-1] != 0:
          self.Z[i] = ( self.Z[i] ^
                        self.antilog_ptr[(self.log_ptr[self.sigma[j]] +
                        self.log_ptr[self.s[(i-j)-1]])] )

    for i in xrange( num_errors ):
      location = self.n - self.errorLocations[i]

      emag = self.Z[0]
      for j in xrange( num_errors ):
        power_of_alpha = ( self.poa * location ) * j

        if power_of_alpha != 0 and self.Z[j] != 0:
          emag = emag ^ self.antilog_ptr[(self.log_ptr[self.Z[j]] +
                                          power_of_alpha)]

      elp = self.sigma[1]
      for j in xrange( elp_max ):
        power_of_alpha = (self.poa * location) * (2 * j)

        if power_of_alpha != 0 and self.sigma[2*j+1] != 0:
          elp = elp ^ self.antilog_ptr[(self.log_ptr[self.sigma[2*j+1]] +
                                        power_of_alpha)]

      emag = self.antilog_ptr[(int)((self.poa * (self.Mo - 1) * location) +
                        self.log_ptr[emag]) % self.modulus]

      elp = self.antilog_ptr[((self.poa * location) + self.log_ptr[elp])]

      if elp == 0:
        return -1

      power_of_alpha = self.n - int( self.log_ptr[elp] )

      if emag != 0 and power_of_alpha != 0:
        self.errorMagnitudes[i] = self.antilog_ptr[self.log_ptr[emag] +
                                                   power_of_alpha]
      else:
        return -1

    return 0

  def rsd_correct_symbols( self, r, interleave, num_errors ):
    for i in xrange( num_errors ):
      actual_location = self.modulus - self.error_locations[i] - 1 - self.vf
      actual_location = ( actual_location * self.I ) + interleave
      r[actual_location] = r[actual_location] ^ self.error_magnitudes[i]
