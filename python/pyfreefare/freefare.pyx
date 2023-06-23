#cython: language_level=3

import enum

import os                 # strerror for desfire key deriver

from libc.stdint cimport uint8_t, uint32_t
from libc.stdlib cimport free

cimport libnfc
from nfc cimport NfcDevice, NfcContext

cimport libfreefare as ff

# define hidden object to prevent calling x.__new__() from python code
cdef object init_key = object()

cdef charp_to_python_str(const char *s):
    return <bytes>(s).decode('utf-8') if s != NULL else None

def get_tags(device: NfcDevice) -> list[Tag]:
    cdef ff.FreefareTag* tags
    tags = ff.freefare_get_tags(device._device)
    if tags is NULL:
        raise MemoryError()

    lst = []
    cdef int i = 0
    while <void*>tags[i] is not NULL:
        lst.append(Tag._create(tags[i], device))
        i += 1
    free(tags)  # only free tag array, not inidividual tags
    return lst

class TagType(enum.Enum):
    FELICA = ff.FELICA
    MIFARE_MINI = ff.MIFARE_MINI
    MIFARE_CLASSIC_1K = ff.MIFARE_CLASSIC_1K
    MIFARE_CLASSIC_4K = ff.MIFARE_CLASSIC_4K
    MIFARE_DESFIRE = ff.MIFARE_DESFIRE
#    MIFARE_PLUS_S2K = ff.MIFARE_PLUS_S2K
#    MIFARE_PLUS_S4K = ff.MIFARE_PLUS_S4K
#    MIFARE_PLUS_X2K = ff.MIFARE_PLUS_X2K
#    MIFARE_PLUS_X4K = ff.MIFARE_PLUS_X4K
    MIFARE_ULTRALIGHT = ff.MIFARE_ULTRALIGHT
    MIFARE_ULTRALIGHT_C = ff.MIFARE_ULTRALIGHT_C
    NTAG_21x = ff.NTAG_21x

cdef class Tag:
    cdef readonly NfcDevice device        # prevent GC of device that owns tag
    cdef ff.FreefareTag _tag

    def __cinit__(self, key, NfcDevice device):
        if key is not init_key:
            raise TypeError("This class cannot be instantiated directly.")
        self.device = device

    def __del__(self):
        self.__dealloc__()

    def __dealloc__(self):
        if <void*>self._tag != NULL:
            ff.freefare_free_tag(self._tag)
            self._tag = NULL

    @staticmethod
    cdef Tag _create(ff.FreefareTag _tag, NfcDevice device):
        if _tag is NULL:
            raise Exception("Can't create Tag from NULL")
        cdef Tag tag
        # create correct class according to tagtype
        cdef ff.freefare_tag_type _tag_type = ff.freefare_get_tag_type(_tag)
        cdef type tag_class
        if _tag_type == ff.MIFARE_DESFIRE:
            tag_class = TagDesfire
        else:
            tag_class = Tag
        tag = tag_class.__new__(tag_class, init_key, device)
        tag._tag = _tag
        return tag

    def connect(self):
        raise NotImplementedError()

    def disconnect(self):
        raise NotImplementedError()

    @property
    def uid_raw(self) -> bytes:
        cdef uint8_t *uid
        cdef int uid_len = ff.freefare_get_tag_uid_raw(self._tag, &uid)
        if uid_len < 0:
            raise Exception('freefare_get_tag_uid_raw() failed')
        return uid[:uid_len]

    @property
    def uid(self) -> str:
        return self.uid_raw.hex()

    @property
    def type(self) -> TagType:
        return TagType(ff.freefare_get_tag_type(self._tag))

    def __repr__(self):
        return f"<{self.__class__.__name__}:{self.type.name} {self.uid}>"

    def is_present(self) -> bool:
        return libnfc.nfc_initiator_target_is_present(self.device._device, ff.freefare_get_tag_target(self._tag)) == libnfc.NFC_SUCCESS

cdef class TagDesfire(Tag):
    def connect(self) -> None:
        self.check_rc(ff.mifare_desfire_connect(self._tag), 'mifare_desfire_connect')

    def disconnect(self) -> None:
        self.check_rc(ff.mifare_desfire_disconnect(self._tag), 'mifare_desfire_disconnect')

    @property
    def last_pcd_error(self) -> int:
        return ff.mifare_desfire_last_pcd_error(self._tag)

    @property
    def last_picc_error(self) -> int:
        return ff.mifare_desfire_last_picc_error(self._tag)

    @property
    def strerror(self) -> str:
        return charp_to_python_str(ff.freefare_strerror(self._tag))

    cdef int check_rc(self, int rc, str where) except -1:
        if rc != 0:
            # TODO - freefare-sepcific exception class
            raise Exception(f"{where} failed: {self.strerror}")
        return rc

    def authenticate(self, key_no: int, key: MifareDESFireKey, fail_ok: bool = True) -> bool:
        cdef rc = ff.mifare_desfire_authenticate(self._tag, key_no, key._key)
        if rc == 0:
            return True
        elif fail_ok and self.last_picc_error == ff.AUTHENTICATION_ERROR:
            return False
        else:
            self.check_rc(rc, 'mifare_desfire_authenticate')

    def get_key_settings(self) -> tuple(int, int):
        cdef uint8_t settings = 0, max_keys = 0
        self.check_rc(ff.mifare_desfire_get_key_settings(self._tag, &settings, &max_keys),
                      'mifare_desfire_get_key_settings')
        return (settings, max_keys)

    def get_version(self) -> int:
        cdef ff.mifare_desfire_version_info info
        self.check_rc(ff.mifare_desfire_get_version(self._tag, &info),
                      'mifare_desfire_get_version')
        cdef object pyinfo = info
        pyinfo['uid'] = info.uid[:sizeof(info.uid)]
        pyinfo['batch_number'] = info.batch_number[:sizeof(info.batch_number)]
        return pyinfo

    def get_application_ids(self) -> list[MifareDESFireAID]:
        cdef ff.MifareDESFireAID *aids = NULL
        cdef size_t count = 0
        self.check_rc(ff.mifare_desfire_get_application_ids(self._tag, &aids, &count),
                      'mifare_desfire_get_application_ids')
        aid_list = []
        for i in range(count):
            aid_list.append(MifareDESFireAID._create(aids[i]))
        free(aids)
        return aid_list

    def get_key_version(self, key_no: int) -> int:
        cdef uint8_t version = 0
        self.check_rc(ff.mifare_desfire_get_key_version(self._tag, key_no, &version),
                      'mifare_desfire_get_key_version')
        return version

    def select_application(self, aid: MifareDESFireAID|int) -> None:
        cdef MifareDESFireAID _aid = MifareDESFireAID(aid) if not isinstance(aid, MifareDESFireAID) else aid
        self.check_rc(ff.mifare_desfire_select_application(self._tag, _aid._aid),
                      'mifare_desfire_select_application')

    def create_application_aes(self, aid: MifareDESFireAID, settings: int, key_no: int) -> None:
        self.check_rc(ff.mifare_desfire_create_application_aes(self._tag, aid._aid, settings, key_no),
                      'mifare_desfire_create_application_aes')

    def change_key(self, key_no: int, new_key: MifareDESFireKey, old_key: MifareDESFireKey | None = None):
        cdef ff.MifareDESFireKey _old_key = (<MifareDESFireKey?>old_key)._key if old_key is not None else NULL
        self.check_rc(ff.mifare_desfire_change_key(self._tag, key_no, new_key._key, _old_key),
                      'mifare_desfire_change_key')

    def change_key_settings(self, settings: int):
        self.check_rc(ff.mifare_desfire_change_key_settings(self._tag, settings),
                      'mifare_desfire_change_key_settings')

cdef class MifareDESFireAID:
    cdef ff.MifareDESFireAID _aid

    def __cinit__(self, aid: int, create_empty: object = None):
        if create_empty is init_key:
            return
        self._aid = ff.mifare_desfire_aid_new(aid)
        if self._aid is NULL:
            raise MemoryError()

    def __dealloc__(self):
        if self._aid is not NULL:
            free(self._aid)
            self._aid = NULL

    @staticmethod
    cdef MifareDESFireAID _create(ff.MifareDESFireAID c_aid):
        if c_aid is NULL:
            raise MemoryError("Can't create AID from NULL")
        aid:MifareDESFireAID  = MifareDESFireAID.__new__(MifareDESFireAID, 0, init_key)
        aid._aid = c_aid
        return aid

    @staticmethod
    def from_mad(application_code: int, function_cluster_code: int, n: int) -> MifareDESFireAID:
        if n >= 16:
            raise TypeError("n must be only 4 bits")
        cdef ff.MadAid madaid = [application_code, function_cluster_code]
        return MifareDESFireAID._create(c_aid = ff.mifare_desfire_aid_new_with_mad_aid(madaid, n))

    @property
    def as_int(self) -> int:
        return ff.mifare_desfire_aid_get_aid(self._aid)

    def __repr__(self):
        return f"<{self.__class__.__name__}:{self.as_int:06x}>"

    def __eq__(self, other: MifareDESFireAID|int):
        if isinstance(other, MifareDESFireAID):
            return self.as_int == other.as_int
        elif isinstance(other, int):
            return self.as_int == other
        else:
            return NotImplemented

class MifareKeyType(enum.Enum):
    DES = ff.MIFARE_KEY_DES
    AES128 = ff.MIFARE_KEY_AES128
    DES2K3 = ff.MIFARE_KEY_2K3DES
    DES3K3 = ff.MIFARE_KEY_3K3DES

cdef class MifareDESFireKey:
    cdef ff.MifareDESFireKey _key

    def __cinit__(self, key: bytes, type: MifareKeyType, version: int|bool|None = None, *, noinit = None):
        if noinit is init_key:
            return
        elif type == MifareKeyType.AES128:
            if len(key) != 16:
                raise ValueError(f"AES128 key must be 16 bytes long, not {len(key)}")
            if version is None:
                self._key = ff.mifare_desfire_aes_key_new(key)
            else:
                self._key = ff.mifare_desfire_aes_key_new_with_version(key, version)
        elif type == MifareKeyType.DES:
            if len(key) != 8:
                raise ValueError(f"DES key must be 8 bytes long, not {len(key)}")
            if version is None:
                self._key = ff.mifare_desfire_des_key_new(key)
            elif version is True:
                self._key = ff.mifare_desfire_des_key_new_with_version(key)
            else:
                self._key = ff.mifare_desfire_des_key_new(key)
                ff.mifare_desfire_key_set_version(self._key, version)
        else:
            raise ValueError(f"Unknown Desfire key type {type}")

    @staticmethod
    cdef MifareDESFireKey _create(ff.MifareDESFireKey c_key):
        cdef MifareDESFireKey key = MifareDESFireKey.__new__(MifareDESFireKey, b'', 0, noinit = init_key)
        key._key = c_key
        return key

    def __dealloc__(self):
        if self._key is not NULL:
            ff.mifare_desfire_key_free(self._key)
            self._key = NULL

    def __repr__(self):
        return f"<{self.__class__.__name__}:{self.type}>"

    @property
    def version(self) -> int:
        return ff.mifare_desfire_key_get_version(self._key)

    def type(self) -> MifareKeyType:
        return MifareKeyType(ff.mifare_desfire_key_get_type(self._key))

cdef class MifareDESFireKeyDeriver:
    cdef readonly MifareDESFireKey master_key
    cdef ff.MifareKeyDeriver _d

    def __cinit__(self, master_key: MifareDESFireKey, output_key_type: MifareKeyType, flags: int = 0):
        self._d = ff.mifare_key_deriver_new_an10922(master_key._key, output_key_type.value, flags)
        if self._d is NULL:
            raise Exception(f"mifare_key_deriver_new_an10922() failed: {os.strerror(os.errno)}")

    def __del__(self):
        self.__dealloc__()

    def __dealloc__(self):
        if self._d is not NULL:
            ff.mifare_key_deriver_free(self._d)
            self._d = NULL

    cdef int check_error(self, rc, where="call") except -1:
        if rc < 0:
            raise Exception(f"{where} failed: {os.strerror(os.errno)}")
        return 0

    def begin(self) -> MifareDESFireKeyDeriver:
         self.check_error(ff.mifare_key_deriver_begin(self._d))
         return self

    def data(self, data: bytes) -> MifareDESFireKeyDeriver:
        self.check_error(ff.mifare_key_deriver_update_data(self._d, data, len(data)))
        return self

    def uid(self, tag: Tag) -> MifareDESFireKeyDeriver:
        self.check_error(ff.mifare_key_deriver_update_uid(self._d, tag._tag))
        return self

    def aid(self, aid: MifareDESFireAID) -> MifareDESFireKeyDeriver:
        self.check_error(ff.mifare_key_deriver_update_aid(self._d, aid._aid))
        return self

    def cstr(self, cstring) -> MifareDESFireKeyDeriver:
        if isinstance(cstring, str):
            cstring = cstring.encode('utf-8')
        self.check_error(ff.mifare_key_deriver_update_cstr(self._d, cstring))
        return self

    def end(self) -> MifareDESFireKey:
        cdef ff.MifareDESFireKey key = ff.mifare_key_deriver_end(self._d)
        if key is NULL:
            return self.check_error(-1)
        return MifareDESFireKey._create(key)
