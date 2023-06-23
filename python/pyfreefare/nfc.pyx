#cython: language_level=3

import enum
from libc.stdlib cimport free
from cpython.mem cimport PyMem_Malloc, PyMem_Free

cimport libnfc

cdef object init_key = object()

cdef const char* bytes_to_charp(bytes s):
    return <const char*>s if s is not None else NULL

cdef class NfcContext:
#   cdef libnfc.nfc_context* _context
    def __dealloc__(self):
        if <void*>self._context is not NULL:
            libnfc.nfc_exit(self._context)
            self._context = NULL

    def __cinit__(self):
        libnfc.nfc_init(&self._context)
        if self._context is NULL:
            raise MemoryError()

    def list_devices(self, max_count: int = 8) -> list[bytes]:
        cdef libnfc.nfc_connstring *connstrings = <libnfc.nfc_connstring*>PyMem_Malloc(max_count * sizeof(libnfc.nfc_connstring))
        if connstrings is NULL:
            raise MemoryError
        cdef count = libnfc.nfc_list_devices(self._context, connstrings, max_count)
        ret = [<bytes>(connstrings[i]) for i in range(count)]
        PyMem_Free(connstrings)
        return ret

    def open_device(self, connstring=None):
        cdef libnfc.nfc_device* pdev = libnfc.nfc_open(self._context, bytes_to_charp(connstring))
        if pdev is NULL:
            raise Exception("nfc_open failed")
        return NfcDevice._create(pdev, self)

cdef class NfcDevice:
#    cdef libnfc.nfc_device* _device
#    cdef public NfcContext context

    def __dealloc__(self):
       if self._device is not NULL:
            libnfc.nfc_close(self._device)
            self._device = NULL

    @staticmethod
    cdef NfcDevice _create(libnfc.nfc_device* _dev, NfcContext context):
        cdef NfcDevice dev = NfcDevice()
        dev._device = _dev
        dev.context = context
        return dev

class NfcErrorCode(enum.Enum):
    NFC_SUCCESS = libnfc.NFC_SUCCESS
    NFC_EIO = libnfc.NFC_EIO
    NFC_EINVARG = libnfc.NFC_EINVARG
    NFC_EDEVNOTSUPP = libnfc.NFC_EDEVNOTSUPP
    NFC_ENOTSUCHDEV = libnfc.NFC_ENOTSUCHDEV
    NFC_EOVFLOW = libnfc.NFC_EOVFLOW
    NFC_ETIMEOUT = libnfc.NFC_ETIMEOUT
    NFC_EOPABORTED = libnfc.NFC_EOPABORTED
    NFC_ENOTIMPL = libnfc.NFC_ENOTIMPL
    NFC_ETGRELEASED = libnfc.NFC_ETGRELEASED
    NFC_ERFTRANS = libnfc.NFC_ERFTRANS
    NFC_EMFCAUTHFAIL = libnfc.NFC_EMFCAUTHFAIL
    NFC_ESOFT = libnfc.NFC_ESOFT
    NFC_ECHIP = libnfc.NFC_ECHIP



