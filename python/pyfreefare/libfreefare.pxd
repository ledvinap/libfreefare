from libc.stdint cimport uint8_t, uint32_t, uint16_t, int32_t
from posix.types cimport off_t
from libnfc cimport nfc_device, nfc_target, nfc_iso14443a_info

cdef extern from *:
   ctypedef unsigned char c_bool "bool"

cdef extern from "freefare.h":
    cpdef enum mifare_key_type:
        MIFARE_KEY_DES
        MIFARE_KEY_2K3DES
        MIFARE_KEY_3K3DES
        MIFARE_KEY_AES128
    ctypedef mifare_key_type MifareKeyType

    cpdef enum freefare_tag_type:
        FELICA
        MIFARE_MINI
        MIFARE_CLASSIC_1K
        MIFARE_CLASSIC_4K
        MIFARE_DESFIRE
        MIFARE_ULTRALIGHT
        MIFARE_ULTRALIGHT_C
        NTAG_21x

    cdef struct freefare_tag
    ctypedef freefare_tag* FreefareTag

    cdef struct mifare_desfire_key
    ctypedef mifare_desfire_key* MifareDESFireKey

    cdef struct ntag21x_key

    ctypedef ntag21x_key* NTAG21xKey

    ctypedef uint8_t MifareUltralightPageNumber

    ctypedef unsigned char MifareUltralightPage[4]

    FreefareTag* freefare_get_tags(nfc_device* device)

    FreefareTag freefare_tag_new(nfc_device* device, nfc_target target)

    freefare_tag_type freefare_get_tag_type(FreefareTag tag)

    const char* freefare_get_tag_friendly_name(FreefareTag tag)

    char* freefare_get_tag_uid(FreefareTag tag)

    int freefare_get_tag_uid_raw(FreefareTag tag, uint8_t** uid)

    nfc_target* freefare_get_tag_target(FreefareTag tag)

    void freefare_free_tag(FreefareTag tag)

    void freefare_free_tags(FreefareTag* tags)

    bint freefare_selected_tag_is_present(nfc_device* device)

    void freefare_set_tag_timeout(FreefareTag tag, int timeout)

    const char* freefare_version()

    const char* freefare_strerror(FreefareTag tag)

    int freefare_strerror_r(FreefareTag tag, char* buffer, size_t len)

    void freefare_perror(FreefareTag tag, const char* string)

    bint felica_taste(nfc_device* device, nfc_target target)

    FreefareTag felica_tag_new(nfc_device* device, nfc_target target)

    void felica_tag_free(FreefareTag tag)

    ssize_t felica_read(FreefareTag tag, uint16_t service, uint8_t block, uint8_t* data, size_t length)

    ssize_t felica_read_ex(FreefareTag tag, uint16_t service, uint8_t block_count, uint8_t blocks[], uint8_t* data, size_t length)

    ssize_t felica_write(FreefareTag tag, uint16_t service, uint8_t block, uint8_t* data, size_t length)

    ssize_t felica_write_ex(FreefareTag tag, uint16_t service, uint8_t block_count, uint8_t blocks[], uint8_t* data, size_t length)

    bint mifare_ultralight_taste(nfc_device* device, nfc_target target)

    bint mifare_ultralightc_taste(nfc_device* device, nfc_target target)

    FreefareTag mifare_ultralight_tag_new(nfc_device* device, nfc_target target)

    FreefareTag mifare_ultralightc_tag_new(nfc_device* device, nfc_target target)

    void mifare_ultralight_tag_free(FreefareTag tag)

    void mifare_ultralightc_tag_free(FreefareTag tag)

    int mifare_ultralight_connect(FreefareTag tag)

    int mifare_ultralight_disconnect(FreefareTag tag)

    int mifare_ultralight_read(FreefareTag tag, const MifareUltralightPageNumber page, MifareUltralightPage* data)

    int mifare_ultralight_write(FreefareTag tag, const MifareUltralightPageNumber page, const MifareUltralightPage data)

    int mifare_ultralightc_authenticate(FreefareTag tag, const MifareDESFireKey key)

    int mifare_ultralightc_set_key(FreefareTag tag, MifareDESFireKey key)

    bint is_mifare_ultralight(FreefareTag tag)

    bint is_mifare_ultralightc(FreefareTag tag)

    bint is_mifare_ultralightc_on_reader(nfc_device* device, nfc_iso14443a_info nai)

    bint ntag21x_taste(nfc_device* device, nfc_target target)

    uint8_t ntag21x_last_error(FreefareTag tag)

    cdef enum ntag_tag_subtype:
        NTAG_UNKNOWN
        NTAG_213
        NTAG_215
        NTAG_216

    FreefareTag ntag21x_tag_new(nfc_device* device, nfc_target target)

    FreefareTag ntag21x_tag_reuse(FreefareTag tag)

    NTAG21xKey ntag21x_key_new(const uint8_t data[4], const uint8_t pack[2])

    void ntag21x_key_free(NTAG21xKey key)

    void ntag21x_tag_free(FreefareTag tag)

    int ntag21x_connect(FreefareTag tag)

    int ntag21x_disconnect(FreefareTag tag)

    int ntag21x_get_info(FreefareTag tag)

    ntag_tag_subtype ntag21x_get_subtype(FreefareTag tag)

    uint8_t ntag21x_get_last_page(FreefareTag tag)

    int ntag21x_read_signature(FreefareTag tag, uint8_t* data)

    int ntag21x_set_pwd(FreefareTag tag, uint8_t data[4])

    int ntag21x_set_pack(FreefareTag tag, uint8_t data[2])

    int ntag21x_set_key(FreefareTag tag, const NTAG21xKey key)

    int ntag21x_set_auth(FreefareTag tag, uint8_t byte)

    int ntag21x_get_auth(FreefareTag tag, uint8_t* byte)

    int ntag21x_access_enable(FreefareTag tag, uint8_t byte)

    int ntag21x_access_disable(FreefareTag tag, uint8_t byte)

    int ntag21x_get_access(FreefareTag tag, uint8_t* byte)

    int ntag21x_check_access(FreefareTag tag, uint8_t byte, c_bool* result)

    int ntag21x_get_authentication_limit(FreefareTag tag, uint8_t* byte)

    int ntag21x_set_authentication_limit(FreefareTag tag, uint8_t byte)

    int ntag21x_read(FreefareTag tag, uint8_t page, uint8_t* data)

    int ntag21x_read4(FreefareTag tag, uint8_t page, uint8_t* data)

    int ntag21x_fast_read(FreefareTag tag, uint8_t start_page, uint8_t end_page, uint8_t* data)

    int ntag21x_fast_read4(FreefareTag tag, uint8_t page, uint8_t* data)

    int ntag21x_read_cnt(FreefareTag tag, uint8_t* data)

    int ntag21x_write(FreefareTag tag, uint8_t page, uint8_t data[4])

    int ntag21x_compatibility_write(FreefareTag tag, uint8_t page, uint8_t data[4])

    int ntag21x_authenticate(FreefareTag tag, const NTAG21xKey key)

    bint is_ntag21x(FreefareTag tag)

    bint ntag21x_is_auth_supported(nfc_device* device, nfc_iso14443a_info nai)

    bint mifare_mini_taste(nfc_device* device, nfc_target target)

    bint mifare_classic1k_taste(nfc_device* device, nfc_target target)

    bint mifare_classic4k_taste(nfc_device* device, nfc_target target)

    FreefareTag mifare_mini_tag_new(nfc_device* device, nfc_target target)

    FreefareTag mifare_classic1k_tag_new(nfc_device* device, nfc_target target)

    FreefareTag mifare_classic4k_tag_new(nfc_device* device, nfc_target target)

    void mifare_classic_tag_free(FreefareTag tag)

    ctypedef unsigned char[16] MifareClassicBlock

    ctypedef uint8_t MifareClassicSectorNumber

    ctypedef unsigned char MifareClassicBlockNumber

    ctypedef enum MifareClassicKeyType:
        MFC_KEY_A
        MFC_KEY_B

    ctypedef unsigned char MifareClassicKey[6]

    const MifareClassicKey mifare_classic_nfcforum_public_key_a

    int mifare_classic_connect(FreefareTag tag)

    int mifare_classic_disconnect(FreefareTag tag)

    int mifare_classic_authenticate(FreefareTag tag, const MifareClassicBlockNumber block, const MifareClassicKey key, const MifareClassicKeyType key_type)

    int mifare_classic_read(FreefareTag tag, const MifareClassicBlockNumber block, MifareClassicBlock* data)

    int mifare_classic_init_value(FreefareTag tag, const MifareClassicBlockNumber block, const int32_t value, const MifareClassicBlockNumber adr)

    int mifare_classic_read_value(FreefareTag tag, const MifareClassicBlockNumber block, int32_t* value, MifareClassicBlockNumber* adr)

    int mifare_classic_write(FreefareTag tag, const MifareClassicBlockNumber block, const MifareClassicBlock data)

    int mifare_classic_increment(FreefareTag tag, const MifareClassicBlockNumber block, const uint32_t amount)

    int mifare_classic_decrement(FreefareTag tag, const MifareClassicBlockNumber block, const uint32_t amount)

    int mifare_classic_restore(FreefareTag tag, const MifareClassicBlockNumber block)

    int mifare_classic_transfer(FreefareTag tag, const MifareClassicBlockNumber block)

    int mifare_classic_get_trailer_block_permission(FreefareTag tag, const MifareClassicBlockNumber block, const uint16_t permission, const MifareClassicKeyType key_type)

    int mifare_classic_get_data_block_permission(FreefareTag tag, const MifareClassicBlockNumber block, const unsigned char permission, const MifareClassicKeyType key_type)

    int mifare_classic_format_sector(FreefareTag tag, const MifareClassicSectorNumber sector)

    void mifare_classic_trailer_block(MifareClassicBlock* block, const MifareClassicKey key_a, uint8_t ab_0, uint8_t ab_1, uint8_t ab_2, uint8_t ab_tb, const uint8_t gpb, const MifareClassicKey key_b)

    MifareClassicSectorNumber mifare_classic_block_sector(MifareClassicBlockNumber block)

    MifareClassicBlockNumber mifare_classic_sector_first_block(MifareClassicSectorNumber sector)

    size_t mifare_classic_sector_block_count(MifareClassicSectorNumber sector)

    MifareClassicBlockNumber mifare_classic_sector_last_block(MifareClassicSectorNumber sector)

    cdef struct mad_aid:
        uint8_t application_code
        uint8_t function_cluster_code

    ctypedef mad_aid MadAid

    cdef struct mad

    ctypedef mad* Mad

    const MifareClassicKey mad_public_key_a

    const MadAid mad_free_aid

    const MadAid mad_defect_aid

    const MadAid mad_reserved_aid

    const MadAid mad_card_holder_aid

    const MadAid mad_not_applicable_aid

    const MadAid mad_nfcforum_aid

    Mad mad_new(const uint8_t version)

    Mad mad_read(FreefareTag tag)

    int mad_write(FreefareTag tag, Mad mad, const MifareClassicKey key_b_sector_00, const MifareClassicKey key_b_sector_10)

    int mad_get_version(Mad mad)

    void mad_set_version(Mad mad, const uint8_t version)

    MifareClassicSectorNumber mad_get_card_publisher_sector(Mad mad)

    int mad_set_card_publisher_sector(Mad mad, const MifareClassicSectorNumber cps)

    int mad_get_aid(Mad mad, const MifareClassicSectorNumber sector, MadAid* aid)

    int mad_set_aid(Mad mad, const MifareClassicSectorNumber sector, MadAid aid)

    bint mad_sector_reserved(const MifareClassicSectorNumber sector)

    void mad_free(Mad mad)

    MifareClassicSectorNumber* mifare_application_alloc(Mad mad, const MadAid aid, const size_t size)

    ssize_t mifare_application_read(FreefareTag tag, Mad mad, const MadAid aid, void* buf, size_t nbytes, const MifareClassicKey key, const MifareClassicKeyType key_type)

    ssize_t mifare_application_write(FreefareTag tag, Mad mad, const MadAid aid, const void* buf, size_t nbytes, const MifareClassicKey key, const MifareClassicKeyType key_type)

    int mifare_application_free(Mad mad, const MadAid aid)

    MifareClassicSectorNumber* mifare_application_find(Mad mad, const MadAid aid)

    bint mifare_desfire_taste(nfc_device* device, nfc_target target)

    cpdef enum mifare_desfire_file_types:
        MDFT_STANDARD_DATA_FILE
        MDFT_BACKUP_DATA_FILE
        MDFT_VALUE_FILE_WITH_BACKUP
        MDFT_LINEAR_RECORD_FILE_WITH_BACKUP
        MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP

    cdef const int OPERATION_OK
    cdef const int NO_CHANGES
    cdef const int OUT_OF_EEPROM_ERROR
    cdef const int ILLEGAL_COMMAND_CODE
    cdef const int INTEGRITY_ERROR
    cdef const int NO_SUCH_KEY
    cdef const int LENGTH_ERROR
    cdef const int PERMISSION_ERROR
    cdef const int PARAMETER_ERROR
    cdef const int APPLICATION_NOT_FOUND
    cdef const int APPL_INTEGRITY_ERROR
    cdef const int AUTHENTICATION_ERROR
    cdef const int ADDITIONAL_FRAME
    cdef const int BOUNDARY_ERROR
    cdef const int PICC_INTEGRITY_ERROR
    cdef const int COMMAND_ABORTED
    cdef const int PICC_DISABLED_ERROR
    cdef const int COUNT_ERROR
    cdef const int DUPLICATE_ERROR
    cdef const int EEPROM_ERROR
    cdef const int FILE_NOT_FOUND
    cdef const int FILE_INTEGRITY_ERROR

    cdef struct mifare_desfire_aid

    ctypedef mifare_desfire_aid* MifareDESFireAID

    cdef struct mifare_desfire_df:
        uint32_t aid
        uint16_t fid
        uint8_t df_name[16]
        size_t df_name_len

    ctypedef mifare_desfire_df MifareDESFireDF

    MifareDESFireAID mifare_desfire_aid_new(uint32_t aid)

    MifareDESFireAID mifare_desfire_aid_new_with_mad_aid(MadAid mad_aid, uint8_t n)

    uint32_t mifare_desfire_aid_get_aid(MifareDESFireAID aid)

    uint8_t mifare_desfire_last_pcd_error(FreefareTag tag)

    uint8_t mifare_desfire_last_picc_error(FreefareTag tag)

    cdef struct mifare_desfire_version_info_hw:
        uint8_t vendor_id
        uint8_t type
        uint8_t subtype
        uint8_t version_major
        uint8_t version_minor
        uint8_t storage_size
        uint8_t protocol

    cdef struct mifare_desfire_version_info_sw:
        uint8_t vendor_id
        uint8_t type
        uint8_t subtype
        uint8_t version_major
        uint8_t version_minor
        uint8_t storage_size
        uint8_t protocol

    cdef struct mifare_desfire_version_info:
        mifare_desfire_version_info_hw hardware
        mifare_desfire_version_info_sw software
        uint8_t[7] uid
        uint8_t[5] batch_number
        uint8_t production_week
        uint8_t production_year

    cdef struct _mifare_desfire_file_settings_settings_settings_standard_file_s:
        uint32_t file_size

    cdef struct _mifare_desfire_file_settings_settings_settings_value_file_s:
        int32_t lower_limit
        int32_t upper_limit
        int32_t limited_credit_value
        uint8_t limited_credit_enabled

    cdef struct _mifare_desfire_file_settings_settings_settings_linear_record_file_s:
        uint32_t record_size
        uint32_t max_number_of_records
        uint32_t current_number_of_records

    cdef union _mifare_desfire_file_settings_settings_u:
        _mifare_desfire_file_settings_settings_settings_standard_file_s standard_file
        _mifare_desfire_file_settings_settings_settings_value_file_s value_file
        _mifare_desfire_file_settings_settings_settings_linear_record_file_s linear_record_file

    cdef struct mifare_desfire_file_settings:
        uint8_t file_type
        uint8_t communication_settings
        uint16_t access_rights
        _mifare_desfire_file_settings_settings_u settings

    FreefareTag mifare_desfire_tag_new(nfc_device* device, nfc_target target)

    void mifare_desfire_tag_free(FreefareTag tags)

    int mifare_desfire_connect(FreefareTag tag)

    int mifare_desfire_disconnect(FreefareTag tag)

    int mifare_desfire_authenticate(FreefareTag tag, uint8_t key_no, MifareDESFireKey key)

    int mifare_desfire_authenticate_iso(FreefareTag tag, uint8_t key_no, MifareDESFireKey key)

    int mifare_desfire_authenticate_aes(FreefareTag tag, uint8_t key_no, MifareDESFireKey key)

    int mifare_desfire_change_key_settings(FreefareTag tag, uint8_t settings)

    int mifare_desfire_get_key_settings(FreefareTag tag, uint8_t* settings, uint8_t* max_keys)

    int mifare_desfire_change_key(FreefareTag tag, uint8_t key_no, MifareDESFireKey new_key, MifareDESFireKey old_key)

    int mifare_desfire_get_key_version(FreefareTag tag, uint8_t key_no, uint8_t* version)

    int mifare_desfire_create_application(FreefareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no)

    int mifare_desfire_create_application_3k3des(FreefareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no)

    int mifare_desfire_create_application_aes(FreefareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no)

    int mifare_desfire_create_application_iso(FreefareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no, int want_iso_file_identifiers, uint16_t iso_file_id, uint8_t* iso_file_name, size_t iso_file_name_len)

    int mifare_desfire_create_application_3k3des_iso(FreefareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no, int want_iso_file_identifiers, uint16_t iso_file_id, uint8_t* iso_file_name, size_t iso_file_name_len)

    int mifare_desfire_create_application_aes_iso(FreefareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no, int want_iso_file_identifiers, uint16_t iso_file_id, uint8_t* iso_file_name, size_t iso_file_name_len)

    int mifare_desfire_delete_application(FreefareTag tag, MifareDESFireAID aid)

    int mifare_desfire_get_application_ids(FreefareTag tag, MifareDESFireAID* aids[], size_t* count)

    int mifare_desfire_get_df_names(FreefareTag tag, MifareDESFireDF* dfs[], size_t* count)

    void mifare_desfire_free_application_ids(MifareDESFireAID aids[])

    int mifare_desfire_select_application(FreefareTag tag, MifareDESFireAID aid)

    int mifare_desfire_format_picc(FreefareTag tag)

    int mifare_desfire_get_version(FreefareTag tag, mifare_desfire_version_info* version_info)

    int mifare_desfire_free_mem(FreefareTag tag, uint32_t* size)

    int mifare_desfire_set_configuration(FreefareTag tag, bint disable_format, bint enable_random_uid)

    int mifare_desfire_set_default_key(FreefareTag tag, MifareDESFireKey key)

    int mifare_desfire_set_ats(FreefareTag tag, uint8_t* ats)

    int mifare_desfire_get_card_uid(FreefareTag tag, char** uid)

    int mifare_desfire_get_card_uid_raw(FreefareTag tag, uint8_t uid[7])

    int mifare_desfire_get_file_ids(FreefareTag tag, uint8_t** files, size_t* count)

    int mifare_desfire_get_iso_file_ids(FreefareTag tag, uint16_t** files, size_t* count)

    int mifare_desfire_get_file_settings(FreefareTag tag, uint8_t file_no, mifare_desfire_file_settings* settings)

    int mifare_desfire_change_file_settings(FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights)

    int mifare_desfire_create_std_data_file(FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size)

    int mifare_desfire_create_std_data_file_iso(FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size, uint16_t iso_file_id)

    int mifare_desfire_create_backup_data_file(FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size)

    int mifare_desfire_create_backup_data_file_iso(FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size, uint16_t iso_file_id)

    int mifare_desfire_create_value_file(FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, int32_t lower_limit, int32_t upper_limit, int32_t value, uint8_t limited_credit_enable)

    int mifare_desfire_create_linear_record_file(FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records)

    int mifare_desfire_create_linear_record_file_iso(FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records, uint16_t iso_file_id)

    int mifare_desfire_create_cyclic_record_file(FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records)

    int mifare_desfire_create_cyclic_record_file_iso(FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records, uint16_t iso_file_id)

    int mifare_desfire_delete_file(FreefareTag tag, uint8_t file_no)

    ssize_t mifare_desfire_read_data(FreefareTag tag, uint8_t file_no, off_t offset, size_t length, void* data)

    ssize_t mifare_desfire_read_data_ex(FreefareTag tag, uint8_t file_no, off_t offset, size_t length, void* data, int cs)

    ssize_t mifare_desfire_write_data(FreefareTag tag, uint8_t file_no, off_t offset, size_t length, const void* data)

    ssize_t mifare_desfire_write_data_ex(FreefareTag tag, uint8_t file_no, off_t offset, size_t length, const void* data, int cs)

    int mifare_desfire_get_value(FreefareTag tag, uint8_t file_no, int32_t* value)

    int mifare_desfire_get_value_ex(FreefareTag tag, uint8_t file_no, int32_t* value, int cs)

    int mifare_desfire_credit(FreefareTag tag, uint8_t file_no, int32_t amount)

    int mifare_desfire_credit_ex(FreefareTag tag, uint8_t file_no, int32_t amount, int cs)

    int mifare_desfire_debit(FreefareTag tag, uint8_t file_no, int32_t amount)

    int mifare_desfire_debit_ex(FreefareTag tag, uint8_t file_no, int32_t amount, int cs)

    int mifare_desfire_limited_credit(FreefareTag tag, uint8_t file_no, int32_t amount)

    int mifare_desfire_limited_credit_ex(FreefareTag tag, uint8_t file_no, int32_t amount, int cs)

    ssize_t mifare_desfire_write_record(FreefareTag tag, uint8_t file_no, off_t offset, size_t length, void* data)

    ssize_t mifare_desfire_write_record_ex(FreefareTag tag, uint8_t file_no, off_t offset, size_t length, void* data, int cs)

    ssize_t mifare_desfire_read_records(FreefareTag tag, uint8_t file_no, off_t offset, size_t length, void* data)

    ssize_t mifare_desfire_read_records_ex(FreefareTag tag, uint8_t file_no, off_t offset, size_t length, void* data, int cs)

    int mifare_desfire_clear_record_file(FreefareTag tag, uint8_t file_no)

    int mifare_desfire_commit_transaction(FreefareTag tag)

    int mifare_desfire_abort_transaction(FreefareTag tag)

    MifareDESFireKey mifare_desfire_des_key_new(const uint8_t value[8])

    MifareDESFireKey mifare_desfire_3des_key_new(const uint8_t value[16])

    MifareDESFireKey mifare_desfire_des_key_new_with_version(const uint8_t value[8])

    MifareDESFireKey mifare_desfire_3des_key_new_with_version(const uint8_t value[16])

    MifareDESFireKey mifare_desfire_3k3des_key_new(const uint8_t value[24])

    MifareDESFireKey mifare_desfire_3k3des_key_new_with_version(const uint8_t value[24])

    MifareDESFireKey mifare_desfire_aes_key_new(const uint8_t value[16])

    MifareDESFireKey mifare_desfire_aes_key_new_with_version(const uint8_t value[16], uint8_t version)

    uint8_t mifare_desfire_key_get_version(MifareDESFireKey key)

    void mifare_desfire_key_set_version(MifareDESFireKey key, uint8_t version)

    mifare_key_type mifare_desfire_key_get_type(MifareDESFireKey key);

    void mifare_desfire_key_free(MifareDESFireKey key)

    uint8_t* tlv_encode(const uint8_t type, const uint8_t* istream, uint16_t isize, size_t* osize)

    uint8_t* tlv_decode(const uint8_t* istream, uint8_t* type, uint16_t* size)

    size_t tlv_record_length(const uint8_t* istream, size_t* field_length_size, size_t* field_value_size)

    uint8_t* tlv_append(uint8_t* a, uint8_t* b)

    cdef struct mifare_key_deriver:
        MifareDESFireKey master_key
        MifareKeyType output_key_type
        uint8_t m[32]
        int len
        int flags

    ctypedef mifare_key_deriver* MifareKeyDeriver

    MifareKeyDeriver mifare_key_deriver_new_an10922(MifareDESFireKey master_key, MifareKeyType output_key_type, int flags)

    int mifare_key_deriver_begin(MifareKeyDeriver deriver)

    int mifare_key_deriver_update_data(MifareKeyDeriver deriver, const uint8_t* data, size_t len)

    int mifare_key_deriver_update_uid(MifareKeyDeriver deriver, FreefareTag tag)

    int mifare_key_deriver_update_aid(MifareKeyDeriver deriver, MifareDESFireAID aid)

    int mifare_key_deriver_update_cstr(MifareKeyDeriver deriver, const char* cstr)

    MifareDESFireKey mifare_key_deriver_end(MifareKeyDeriver deriver)

    int mifare_key_deriver_end_raw(MifareKeyDeriver deriver, uint8_t* diversified_bytes, size_t data_max_len)

    void mifare_key_deriver_free(MifareKeyDeriver state)
