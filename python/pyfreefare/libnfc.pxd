from libc.stdint cimport uint8_t, uint32_t

cdef extern from "nfc/nfc.h":

    enum: NFC_SUCCESS
    enum: NFC_EIO
    enum: NFC_EINVARG
    enum: NFC_EDEVNOTSUPP
    enum: NFC_ENOTSUCHDEV
    enum: NFC_EOVFLOW
    enum: NFC_ETIMEOUT
    enum: NFC_EOPABORTED
    enum: NFC_ENOTIMPL
    enum: NFC_ETGRELEASED
    enum: NFC_ERFTRANS
    enum: NFC_EMFCAUTHFAIL
    enum: NFC_ESOFT
    enum: NFC_ECHIP


    ctypedef char[1024] nfc_connstring

    ctypedef enum nfc_property:
        NP_TIMEOUT_COMMAND
        NP_TIMEOUT_ATR
        NP_TIMEOUT_COM
        NP_HANDLE_CRC
        NP_HANDLE_PARITY
        NP_ACTIVATE_FIELD
        NP_ACTIVATE_CRYPTO1
        NP_INFINITE_SELECT
        NP_ACCEPT_INVALID_FRAMES
        NP_ACCEPT_MULTIPLE_FRAMES
        NP_AUTO_ISO14443_4
        NP_EASY_FRAMING
        NP_FORCE_ISO14443_A
        NP_FORCE_ISO14443_B
        NP_FORCE_SPEED_106

    ctypedef enum nfc_dep_mode:
        NDM_UNDEFINED
        NDM_PASSIVE
        NDM_ACTIVE

    ctypedef struct nfc_dep_info:
        uint8_t[10] abtNFCID3
        uint8_t btDID
        uint8_t btBS
        uint8_t btBR
        uint8_t btTO
        uint8_t btPP
        uint8_t[48] abtGB
        size_t szGB
        nfc_dep_mode ndm

    ctypedef struct nfc_iso14443a_info:
        uint8_t[2] abtAtqa
        uint8_t btSak
        size_t szUidLen
        uint8_t[10] abtUid
        size_t szAtsLen
        uint8_t[254] abtAts

    ctypedef struct nfc_felica_info:
        size_t szLen
        uint8_t btResCode
        uint8_t[8] abtId
        uint8_t[8] abtPad
        uint8_t[2] abtSysCode

    ctypedef struct nfc_iso14443b_info:
        uint8_t[4] abtPupi
        uint8_t[4] abtApplicationData
        uint8_t[3] abtProtocolInfo
        uint8_t ui8CardIdentifier

    ctypedef struct nfc_iso14443bi_info:
        uint8_t[4] abtDIV
        uint8_t btVerLog
        uint8_t btConfig
        size_t szAtrLen
        uint8_t[33] abtAtr

    ctypedef struct nfc_iso14443biclass_info:
        uint8_t[8] abtUID

    ctypedef struct nfc_iso14443b2sr_info:
        uint8_t[8] abtUID

    ctypedef struct nfc_iso14443b2ct_info:
        uint8_t[4] abtUID
        uint8_t btProdCode
        uint8_t btFabCode

    ctypedef struct nfc_jewel_info:
        uint8_t[2] btSensRes
        uint8_t[4] btId

    ctypedef struct nfc_barcode_info:
        size_t szDataLen
        uint8_t[32] abtData

    ctypedef union nfc_target_info:
        nfc_iso14443a_info nai
        nfc_felica_info nfi
        nfc_iso14443b_info nbi
        nfc_iso14443bi_info nii
        nfc_iso14443b2sr_info nsi
        nfc_iso14443b2ct_info nci
        nfc_jewel_info nji
        nfc_dep_info ndi
        nfc_barcode_info nti
        nfc_iso14443biclass_info nhi

    ctypedef enum nfc_baud_rate:
        NBR_UNDEFINED
        NBR_106
        NBR_212
        NBR_424
        NBR_847

    ctypedef enum nfc_modulation_type:
        NMT_ISO14443A
        NMT_JEWEL
        NMT_ISO14443B
        NMT_ISO14443BI
        NMT_ISO14443B2SR
        NMT_ISO14443B2CT
        NMT_FELICA
        NMT_DEP
        NMT_BARCODE
        NMT_ISO14443BICLASS
        NMT_END_ENUM

    ctypedef enum nfc_mode:
        N_TARGET
        N_INITIATOR

    ctypedef struct nfc_modulation:
        nfc_modulation_type nmt
        nfc_baud_rate nbr

    ctypedef struct nfc_target:
        nfc_target_info nti
        nfc_modulation nm

    ctypedef struct nfc_context:
        pass

    ctypedef struct nfc_driver:
        pass

    ctypedef struct nfc_device:
        pass

    void nfc_init(nfc_context** context)

    void nfc_exit(nfc_context* context)

    int nfc_register_driver(const nfc_driver* driver)

    nfc_device* nfc_open(nfc_context* context, const nfc_connstring connstring)

    void nfc_close(nfc_device* pnd)

    int nfc_abort_command(nfc_device* pnd)

    size_t nfc_list_devices(nfc_context* context, nfc_connstring[] connstrings, size_t connstrings_len)

    int nfc_idle(nfc_device* pnd)

    int nfc_initiator_init(nfc_device* pnd)

    int nfc_initiator_init_secure_element(nfc_device* pnd)

    int nfc_initiator_select_passive_target(nfc_device* pnd, const nfc_modulation nm, const uint8_t* pbtInitData, const size_t szInitData, nfc_target* pnt)

    int nfc_initiator_list_passive_targets(nfc_device* pnd, const nfc_modulation nm, nfc_target[] ant, const size_t szTargets)

    int nfc_initiator_poll_target(nfc_device* pnd, const nfc_modulation* pnmTargetTypes, const size_t szTargetTypes, const uint8_t uiPollNr, const uint8_t uiPeriod, nfc_target* pnt)

    int nfc_initiator_select_dep_target(nfc_device* pnd, const nfc_dep_mode ndm, const nfc_baud_rate nbr, const nfc_dep_info* pndiInitiator, nfc_target* pnt, const int timeout)

    int nfc_initiator_poll_dep_target(nfc_device* pnd, const nfc_dep_mode ndm, const nfc_baud_rate nbr, const nfc_dep_info* pndiInitiator, nfc_target* pnt, const int timeout)

    int nfc_initiator_deselect_target(nfc_device* pnd)

    int nfc_initiator_transceive_bytes(nfc_device* pnd, const uint8_t* pbtTx, const size_t szTx, uint8_t* pbtRx, const size_t szRx, int timeout)

    int nfc_initiator_transceive_bits(nfc_device* pnd, const uint8_t* pbtTx, const size_t szTxBits, const uint8_t* pbtTxPar, uint8_t* pbtRx, const size_t szRx, uint8_t* pbtRxPar)

    int nfc_initiator_transceive_bytes_timed(nfc_device* pnd, const uint8_t* pbtTx, const size_t szTx, uint8_t* pbtRx, const size_t szRx, uint32_t* cycles)

    int nfc_initiator_transceive_bits_timed(nfc_device* pnd, const uint8_t* pbtTx, const size_t szTxBits, const uint8_t* pbtTxPar, uint8_t* pbtRx, const size_t szRx, uint8_t* pbtRxPar, uint32_t* cycles)

    bint nfc_initiator_target_is_present(nfc_device* pnd, const nfc_target* pnt)

    int nfc_target_init(nfc_device* pnd, nfc_target* pnt, uint8_t* pbtRx, const size_t szRx, int timeout)

    int nfc_target_send_bytes(nfc_device* pnd, const uint8_t* pbtTx, const size_t szTx, int timeout)

    int nfc_target_receive_bytes(nfc_device* pnd, uint8_t* pbtRx, const size_t szRx, int timeout)

    int nfc_target_send_bits(nfc_device* pnd, const uint8_t* pbtTx, const size_t szTxBits, const uint8_t* pbtTxPar)

    int nfc_target_receive_bits(nfc_device* pnd, uint8_t* pbtRx, const size_t szRx, uint8_t* pbtRxPar)

    const char* nfc_strerror(const nfc_device* pnd)

    int nfc_strerror_r(const nfc_device* pnd, char* buf, size_t buflen)

    void nfc_perror(const nfc_device* pnd, const char* s)

    int nfc_device_get_last_error(const nfc_device* pnd)

    const char* nfc_device_get_name(nfc_device* pnd)

    const char* nfc_device_get_connstring(nfc_device* pnd)

    int nfc_device_get_supported_modulation(nfc_device* pnd, const nfc_mode mode, const nfc_modulation_type**  supported_mt)

    int nfc_device_get_supported_baud_rate(nfc_device* pnd, const nfc_modulation_type nmt, const nfc_baud_rate** supported_br)

    int nfc_device_get_supported_baud_rate_target_mode(nfc_device* pnd, const nfc_modulation_type nmt, const nfc_baud_rate** supported_br)

    int nfc_device_set_property_int(nfc_device* pnd, const nfc_property property, const int value)

    int nfc_device_set_property_bool(nfc_device* pnd, const nfc_property property, const bint bEnable)

    void iso14443a_crc(uint8_t* pbtData, size_t szLen, uint8_t* pbtCrc)

    void iso14443a_crc_append(uint8_t* pbtData, size_t szLen)

    void iso14443b_crc(uint8_t* pbtData, size_t szLen, uint8_t* pbtCrc)

    void iso14443b_crc_append(uint8_t* pbtData, size_t szLen)

    uint8_t* iso14443a_locate_historical_bytes(uint8_t* pbtAts, size_t szAts, size_t* pszTk)

    void nfc_free(void* p)

    const char* nfc_version()

    int nfc_device_get_information_about(nfc_device* pnd, char** buf)

    const char* str_nfc_modulation_type(const nfc_modulation_type nmt)

    const char* str_nfc_baud_rate(const nfc_baud_rate nbr)

    int str_nfc_target(char** buf, const nfc_target* pnt, bint verbose)
