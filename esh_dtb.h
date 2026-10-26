#pragma once

#include <stddef.h>
#include <stdint.h>

typedef enum {
    ESHD_RESULT_OK = 0,
    ESHD_RESULT_NOT_ALIGNED,
    ESHD_RESULT_INVALID_HEADER,
    ESHD_RESULT_UNSUPPORTED_VERSION,
    ESHD_RESULT_MALFORMED,
} eshd_result;

typedef struct {
    size_t offset, size;
} eshd_block;

typedef struct {
    uintptr_t base;
    size_t length;
    size_t rsvmap_offset;
    eshd_block structures;
    eshd_block strings;
} eshd_dtb;

typedef struct {
    size_t offset;
} eshd_node;

typedef struct {
    size_t offset;
} eshd_prop;

typedef struct {
    const char *ptr;
    size_t length;
} eshd_string;

typedef struct {
    const void *ptr;
    size_t length;
} eshd_bytes;

eshd_result eshd_init(void *dtb_blob, size_t blob_size, eshd_dtb *dtb);

eshd_node eshd_root(eshd_dtb *dtb);
bool eshd_first_child(eshd_dtb *dtb, eshd_node parent, eshd_node *node);
bool eshd_next_sibling(eshd_dtb *dtb, eshd_node sibling, eshd_node *node);
bool eshd_first_prop(eshd_dtb *dtb, eshd_node node, eshd_prop *prop);
bool eshd_next_prop(eshd_dtb *dtb, eshd_prop prop, eshd_prop *next);

eshd_string eshd_node_name(eshd_dtb *dtb, eshd_node node);

void eshd_prop_pair(eshd_dtb *dtb, eshd_prop prop, eshd_string *name, eshd_bytes *data);
eshd_string eshd_prop_name(eshd_dtb *dtb, eshd_prop prop);
eshd_bytes eshd_prop_value(eshd_dtb *dtb, eshd_prop prop);

bool eshd_find_next_compatible(eshd_dtb *dtb, eshd_node current, const char *str, eshd_node *next);

bool eshd_find_prop(eshd_dtb *dtb, eshd_node node, const char *name, eshd_prop *prop);
bool eshd_find_child(eshd_dtb *dtb, eshd_node parent, const char *name, eshd_node *child);

bool eshd_bytes_extract_u32(eshd_bytes bytes, size_t index, uint32_t *value);

bool eshd_string_eq(eshd_string string, const char *str);
bool eshd_bytes_eq_str(eshd_bytes bytes, const char *str);
int eshd_bytes_eq_str_index(eshd_bytes bytes, size_t string_index, const char *str);

#ifdef ESH_DTB_IMPL

#ifndef ESH_ASSERT
#define ESH_ASSERT(EXPR)
#endif

#define HEADER_MAGIC 0xd00dfeed

#define SUPPORTED_VERSION 17
#define OLDEST_COMPATIBLE_VERSION 17

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define MSB_TO_HOST_16(VALUE) __builtin_bswap16((VALUE))
#define MSB_TO_HOST_32(VALUE) __builtin_bswap32((VALUE))
#define MSB_TO_HOST_64(VALUE) __builtin_bswap64((VALUE))
#else
#define MSB_TO_HOST_16(VALUE) (VALUE)
#define MSB_TO_HOST_32(VALUE) (VALUE)
#define MSB_TO_HOST_64(VALUE) (VALUE)
#endif

#define TOKEN_BEGIN_NODE 1
#define TOKEN_END_NODE 2
#define TOKEN_PROP 3
#define TOKEN_NOP 4
#define TOKEN_END 9

typedef struct {
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
} esh_dt_header;

typedef struct {
    uint64_t address;
    uint64_t size;
} esh_dt_reserve_entry;


// ========== UTIL ==========

static eshd_string eshd_strings_read(eshd_dtb *dtb, size_t offset) {
    size_t original_offset = offset;
    while(*(char *) (dtb->base + dtb->strings.offset + offset) != '\0') offset++;
    return (eshd_string) {
        .ptr = (char *) (dtb->base + dtb->strings.offset + original_offset),
        .length = offset - original_offset,
    };
}

static uint32_t eshd_structs_read_32(eshd_dtb *dtb, size_t offset) {
    return MSB_TO_HOST_32(*(uint32_t *) (dtb->base + dtb->structures.offset + offset));
}

static void eshd_structs_read_string(eshd_dtb *dtb, size_t *offset, eshd_string *str) {
    size_t original_offset = *offset;
    while(*(char *) (dtb->base + dtb->structures.offset + *offset) != '\0') (*offset)++;

    size_t length = *offset - original_offset;
    (*offset)++;

    if(*offset % 4 != 0) *offset += 4 - (*offset % 4);

    if(str != nullptr) {
        str->ptr = (const char *) dtb->base + dtb->structures.offset + original_offset;
        str->length = length;
    }
}

static void eshd_structs_read_property_data(eshd_dtb *dtb, size_t *offset, eshd_string *name, eshd_bytes *bytes) {
    uint32_t bytes_length = eshd_structs_read_32(dtb, *offset);
    *offset += 4;

    uint32_t name_offset = eshd_structs_read_32(dtb, *offset);
    *offset += 4;

    size_t bytes_offset = *offset;
    *offset += bytes_length;

    if(*offset % 4 != 0) *offset += 4 - (*offset % 4);

    if(name != nullptr) {
        *name = eshd_strings_read(dtb, name_offset);
    }

    if(bytes != nullptr) {
        bytes->ptr = (const void *) dtb->base + dtb->structures.offset + bytes_offset;
        bytes->length = bytes_length;
    }
}

static void eshd_structs_read_node_begin(eshd_dtb *dtb, size_t *offset, eshd_string *name) {
    [[maybe_unused]] uint32_t token = eshd_structs_read_32(dtb, *offset);
    ESH_ASSERT(token == TOKEN_BEGIN_NODE);
    *offset += 4;

    eshd_structs_read_string(dtb, offset, name);
}

static void eshd_structs_read_prop(eshd_dtb *dtb, size_t *offset, eshd_string *name, eshd_bytes *bytes) {
    [[maybe_unused]] uint32_t token = eshd_structs_read_32(dtb, *offset);
    ESH_ASSERT(token == TOKEN_PROP);
    *offset += 4;

    eshd_structs_read_property_data(dtb, offset, name, bytes);
}

static int eshd_strncmp(const char *lhs, const char *rhs, size_t size) {
    for(size_t i = 0; i < size; i++) {
        unsigned char a = (unsigned char) lhs[i];
        unsigned char b = (unsigned char) rhs[i];

        if(a != b) return a < b ? -1 : 1;

        if(a == '\0') return 0;
    }

    return 0;
}

static size_t eshd_strlen(const char *str) {
    const char *p = str;
    while(*p != '\0') p++;
    return (size_t) (p - str);
}

// ========== INIT ==========

static eshd_result validate_structures(uintptr_t structures_base, size_t structures_length, uintptr_t strings_base, size_t strings_length) {
    size_t depth = 0;
    size_t offset = 0;
    size_t node_count = 0;
    while(true) {
        if(offset + 4 > structures_length) return ESHD_RESULT_MALFORMED;

        uint32_t status = MSB_TO_HOST_32(*(uint32_t *) (structures_base + offset));
        offset += 4;

        switch(status) {
            case TOKEN_BEGIN_NODE:
                if(depth == 0 && node_count != 0) return ESHD_RESULT_MALFORMED;
                while(true) {
                    if(offset + 1 > structures_length) return ESHD_RESULT_MALFORMED;
                    uint8_t value = *(uint8_t *) (structures_base + offset);
                    offset++;
                    if(value == '\0') break;
                }
                if(offset % 4 != 0) offset += 4 - (offset % 4);
                depth++;
                node_count++;
                break;
            case TOKEN_END_NODE:
                if(depth == 0) return ESHD_RESULT_MALFORMED;
                depth--;
                break;
            case TOKEN_PROP:
                if(depth == 0) return ESHD_RESULT_MALFORMED;
                if(offset + 8 > structures_length) return ESHD_RESULT_MALFORMED;

                size_t bytes_length = MSB_TO_HOST_32(*(uint32_t *) (structures_base + offset));
                offset += 4;

                size_t name_offset = MSB_TO_HOST_32(*(uint32_t *) (structures_base + offset));
                offset += 4;

                for(size_t i = name_offset;; i++) {
                    if(i >= strings_length) return ESHD_RESULT_MALFORMED;
                    uint8_t value = *(uint8_t *) (strings_base + i);
                    if(value == '\0') break;
                }

                if(bytes_length % 4 != 0) bytes_length += 4 - (bytes_length % 4);
                offset += bytes_length;

                if(offset > structures_length) return ESHD_RESULT_MALFORMED;
                break;
            case TOKEN_NOP: break;
            case TOKEN_END:
                if(depth != 0 || offset != structures_length || node_count == 0) return ESHD_RESULT_MALFORMED;
                return ESHD_RESULT_OK;
            default: return ESHD_RESULT_MALFORMED;
        }
    }
}

eshd_result eshd_init(void *dtb_blob, size_t blob_size, eshd_dtb *dtb) {
    if(blob_size > 0 && blob_size < sizeof(esh_dt_header)) {
        return ESHD_RESULT_MALFORMED;
    }

    if((uintptr_t) dtb_blob % 8 != 0) {
        return ESHD_RESULT_NOT_ALIGNED;
    }

    const esh_dt_header *header = dtb_blob;

    if(MSB_TO_HOST_32(header->magic) != HEADER_MAGIC) {
        return ESHD_RESULT_INVALID_HEADER;
    }

    if(MSB_TO_HOST_32(header->version) < OLDEST_COMPATIBLE_VERSION) {
        return ESHD_RESULT_UNSUPPORTED_VERSION;
    }

    if(MSB_TO_HOST_32(header->last_comp_version) > SUPPORTED_VERSION) {
        return ESHD_RESULT_UNSUPPORTED_VERSION;
    }

    size_t total_size = MSB_TO_HOST_32(header->totalsize);
    if(blob_size > 0 && total_size > blob_size) {
        return ESHD_RESULT_MALFORMED;
    }

    size_t rsvmap_offset = MSB_TO_HOST_32(header->off_mem_rsvmap);
    size_t structs_offset = MSB_TO_HOST_32(header->off_dt_struct);
    size_t structs_size = MSB_TO_HOST_32(header->size_dt_struct);
    size_t strings_offset = MSB_TO_HOST_32(header->off_dt_strings);
    size_t strings_size = MSB_TO_HOST_32(header->size_dt_strings);

    uintptr_t rsvmap_base = (uintptr_t) dtb_blob + rsvmap_offset;
    if(rsvmap_base % 8 != 0) return ESHD_RESULT_MALFORMED;

    uintptr_t structs_base = (uintptr_t) dtb_blob + structs_offset;
    if(structs_base % 4 != 0) return ESHD_RESULT_MALFORMED;

    if(rsvmap_offset > structs_offset || structs_offset > strings_offset) return ESHD_RESULT_MALFORMED;
    if(structs_offset + structs_size > strings_offset) return ESHD_RESULT_MALFORMED;
    if(strings_offset + strings_size > total_size) return ESHD_RESULT_MALFORMED;

    eshd_result result = validate_structures(structs_base, structs_size, (uintptr_t) dtb_blob + strings_offset, strings_size);
    if(result != ESHD_RESULT_OK) return result;

    dtb->base = (uintptr_t) dtb_blob;
    dtb->length = total_size;
    dtb->rsvmap_offset = rsvmap_offset;
    dtb->structures.offset = structs_offset;
    dtb->structures.size = structs_size;
    dtb->strings.offset = strings_offset;
    dtb->strings.size = strings_size;

    return ESHD_RESULT_OK;
}


// ========== NAVIGATION ==========

eshd_node eshd_root(eshd_dtb *dtb) {
    size_t offset = 0;
    while(true) {
        switch(eshd_structs_read_32(dtb, offset)) {
            case TOKEN_BEGIN_NODE: return (eshd_node) { .offset = offset };
            case TOKEN_NOP:        offset += 4; break;
            default:               ESH_ASSERT(false);
        }
    }
}

bool eshd_next(eshd_dtb *dtb, eshd_node current, eshd_node *node) {
    size_t offset = current.offset;

    eshd_structs_read_node_begin(dtb, &offset, nullptr);

    while(true) {
        switch(eshd_structs_read_32(dtb, offset)) {
            case TOKEN_BEGIN_NODE: node->offset = offset; return true;
            case TOKEN_PROP:
                offset += 4;
                eshd_structs_read_property_data(dtb, &offset, nullptr, nullptr);
                break;
            case TOKEN_END_NODE:
            case TOKEN_NOP:      offset += 4; break;
            case TOKEN_END:      return false;
        }
    }
}

bool eshd_first_child(eshd_dtb *dtb, eshd_node parent, eshd_node *node) {
    size_t offset = parent.offset;

    eshd_structs_read_node_begin(dtb, &offset, nullptr);

    while(true) {
        switch(eshd_structs_read_32(dtb, offset)) {
            case TOKEN_BEGIN_NODE: node->offset = offset; return true;
            case TOKEN_END_NODE:   return false;
            case TOKEN_PROP:
                offset += 4;
                eshd_structs_read_property_data(dtb, &offset, nullptr, nullptr);
                break;
            case TOKEN_NOP: offset += 4; break;
            default:        ESH_ASSERT(false);
        }
    }
}

bool eshd_next_sibling(eshd_dtb *dtb, eshd_node sibling, eshd_node *node) {
    size_t offset = sibling.offset;

    eshd_structs_read_node_begin(dtb, &offset, nullptr);

    size_t depth = 1;
    while(true) {
        switch(eshd_structs_read_32(dtb, offset)) {
            case TOKEN_BEGIN_NODE:
                if(depth == 0) {
                    node->offset = offset;
                    return true;
                }
                depth++;

                offset += 4;
                eshd_structs_read_string(dtb, &offset, nullptr);
                break;
            case TOKEN_END_NODE:
                if(depth == 0) return false;
                depth--;

                offset += 4;
                break;
            case TOKEN_PROP:
                offset += 4;
                eshd_structs_read_property_data(dtb, &offset, nullptr, nullptr);
                break;
            case TOKEN_NOP: offset += 4; break;
            case TOKEN_END: return false;
            default:        ESH_ASSERT(false);
        }
    }
}

bool eshd_first_prop(eshd_dtb *dtb, eshd_node node, eshd_prop *prop) {
    size_t offset = node.offset;

    eshd_structs_read_node_begin(dtb, &offset, nullptr);

    while(true) {
        switch(eshd_structs_read_32(dtb, offset)) {
            case TOKEN_PROP:       prop->offset = offset; return true;
            case TOKEN_NOP:        offset += 4; break;
            case TOKEN_BEGIN_NODE:
            case TOKEN_END_NODE:   return false;
            default:               ESH_ASSERT(false);
        }
    }
}

bool eshd_next_prop(eshd_dtb *dtb, eshd_prop prop, eshd_prop *next) {
    size_t offset = prop.offset;

    eshd_structs_read_prop(dtb, &offset, nullptr, nullptr);

    while(true) {
        switch(eshd_structs_read_32(dtb, offset)) {
            case TOKEN_PROP:       next->offset = offset; return true;
            case TOKEN_NOP:        offset += 4; break;
            case TOKEN_BEGIN_NODE:
            case TOKEN_END_NODE:   return false;
            default:               ESH_ASSERT(false);
        }
    }
}

// ========== DATA ACCESSORS ==========

eshd_string eshd_node_name(eshd_dtb *dtb, eshd_node node) {
    eshd_string name;
    eshd_structs_read_node_begin(dtb, &node.offset, &name);
    return name;
}

void eshd_prop_pair(eshd_dtb *dtb, eshd_prop prop, eshd_string *name, eshd_bytes *data) {
    eshd_structs_read_prop(dtb, &prop.offset, name, data);
}


// ========== HELPERS ==========

eshd_string eshd_prop_name(eshd_dtb *dtb, eshd_prop prop) {
    eshd_string name;
    eshd_prop_pair(dtb, prop, &name, nullptr);
    return name;
}

eshd_bytes eshd_prop_value(eshd_dtb *dtb, eshd_prop prop) {
    eshd_bytes bytes;
    eshd_prop_pair(dtb, prop, nullptr, &bytes);
    return bytes;
}

uint32_t eshd_prop_value_32(eshd_dtb *dtb, eshd_prop prop, size_t index) {
    eshd_bytes bytes;
    eshd_prop_pair(dtb, prop, nullptr, &bytes);
    const uint32_t *values = bytes.ptr;
    return MSB_TO_HOST_32(values[index]);
}

bool eshd_find_prop(eshd_dtb *dtb, eshd_node node, const char *name, eshd_prop *prop) {
    eshd_prop current;
    for(bool found = eshd_first_prop(dtb, node, &current); found; found = eshd_next_prop(dtb, current, &current)) {
        eshd_string prop_name = eshd_prop_name(dtb, current);
        if(!eshd_string_eq(prop_name, name)) continue;

        prop->offset = current.offset;
        return true;
    }

    return false;
}

bool eshd_find_child(eshd_dtb *dtb, eshd_node parent, const char *name, eshd_node *child) {
    eshd_node current;
    for(bool found = eshd_first_child(dtb, parent, &current); found; found = eshd_next_sibling(dtb, current, &current)) {
        eshd_string child_name = eshd_node_name(dtb, current);
        if(!eshd_string_eq(child_name, name)) continue;

        child->offset = current.offset;
        return true;
    }

    return false;
}

bool eshd_find_next_compatible(eshd_dtb *dtb, eshd_node current, const char *str, eshd_node *node) {
    while(eshd_next(dtb, current, &current)) {
        eshd_prop compatible_prop;
        if(!eshd_find_prop(dtb, current, "compatible", &compatible_prop)) continue;

        eshd_bytes compatible_bytes = eshd_prop_value(dtb, compatible_prop);
        for(int i = 0, res = 0; res != -1; i++) {
            res = eshd_bytes_eq_str_index(compatible_bytes, i, str);
            if(res == 0) continue;

            *node = current;
            return true;
        }
    }

    return false;
}

bool eshd_bytes_extract_u32(eshd_bytes bytes, size_t index, uint32_t *value) {
    if((index + 1) * 4 > bytes.length) return false;
    const uint32_t *values = bytes.ptr;
    *value = MSB_TO_HOST_32(values[index]);
    return true;
}

bool eshd_bytes_str_offset(eshd_bytes bytes, size_t index, size_t *offset) {
    const uint8_t *str = bytes.ptr;
    size_t current = 0;
    for(size_t i = 0; i < bytes.length; i++) {
        if(current == index) {
            *offset = i;
            return true;
        }

        if(str[i] == '\0') current++;
    }

    return false;
}

bool eshd_string_eq(eshd_string string, const char *str) {
    size_t str_length = eshd_strlen(str);

    if(string.length != str_length) return false;
    if(str_length == 0) return true;

    return eshd_strncmp(string.ptr, str, str_length) == 0;
}

bool eshd_bytes_eq_str(eshd_bytes bytes, const char *str) {
    size_t str_length = eshd_strlen(str);

    if(bytes.length != str_length + 1) return false;
    if(str_length == 0) return true;

    return eshd_strncmp(bytes.ptr, str, str_length) == 0;
}

int eshd_bytes_eq_str_index(eshd_bytes bytes, size_t string_index, const char *str) {
    size_t offset;
    if(eshd_bytes_str_offset(bytes, string_index, &offset)) return -1;

    size_t str_length = eshd_strlen(str);
    if(bytes.length - offset != str_length + 1) return 0;
    if(str_length == 0) return 1;

    return (eshd_strncmp(bytes.ptr + offset, str, str_length) == 0) ? 1 : 0;
}


#undef HEADER_MAGIC
#undef SUPPORTED_VERSION
#undef OLDEST_COMPATIBLE_VERSION

#undef MSB_TO_HOST_16
#undef MSB_TO_HOST_32
#undef MSB_TO_HOST_64

#undef TOKEN_BEGIN_NODE
#undef TOKEN_END_NODE
#undef TOKEN_PROP
#undef TOKEN_NOP
#undef TOKEN_END

#endif
