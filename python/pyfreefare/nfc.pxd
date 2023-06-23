#cython: language_level=3

cimport libnfc

cdef class NfcContext:
   cdef libnfc.nfc_context* _context

cdef class NfcDevice:
    cdef libnfc.nfc_device* _device
    cdef readonly NfcContext context

    @staticmethod
    cdef NfcDevice _create(libnfc.nfc_device* _dev, NfcContext context)
