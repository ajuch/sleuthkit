/*
 ** btrfs_io.c
 ** The  Sleuth Kit
 **
 ** I/O utility methods for Btrfs.
 **
 ** Andreas Juch [andreas.juch@gmail.com]
 ** Copyright (c) 2013-1014 Andreas Juch
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file btrfs_io.c
 * Btrfs IO functions
 */

#include "tsk_fs_i.h"
#include "tsk_btrfs.h"
#include <assert.h>

/*
 * Helper Methods.
 */

void
btrfs_io_append_uint8_t(char *buffer, char *desc, uint8_t val) {
    strcat(buffer, ", ");
    strcat(buffer, desc);
    strcat(buffer, ": ");
    char tmp[32] = "";
    btrfs_io_print_uint8_t(tmp, val);
    strcat(buffer, tmp);
}

void
btrfs_io_append_uint16_t(char *buffer, char *desc, uint8_t val) {
    strcat(buffer, ", ");
    strcat(buffer, desc);
    strcat(buffer, ": ");
    char tmp[32] = "";
    btrfs_io_print_uint16_t(tmp, val);
    strcat(buffer, tmp);
}

void
btrfs_io_append_uint32_t(char *buffer, char *desc, uint64_t val) {
    strcat(buffer, ", ");
    strcat(buffer, desc);
    strcat(buffer, ": ");
    char tmp[32] = "";
    btrfs_io_print_uint32_t(tmp, val);
    strcat(buffer, tmp);
}

void
btrfs_io_append_uint64_t(char *buffer, char *desc, uint64_t val) {
    strcat(buffer, ", ");
    strcat(buffer, desc);
    strcat(buffer, ": ");
    char tmp[32] = "";
    btrfs_io_print_uint64_t(tmp, val);
    strcat(buffer, tmp);
}

void
btrfs_io_append_string(char *buffer, char *desc, char *val) {
    strcat(buffer, ", ");
    strcat(buffer, desc);
    strcat(buffer, ": ");
    strcat(buffer, val);
}

void
btrfs_io_check_dimensions(ssize_t read, ssize_t available) {
    if (read > available) {
        printf("ERROR read more bytes than available!\n");
    } else if (read < available) {
        printf("WARN read less bytes than available: %llu of %llu\n", read,
                available);
    } else if (read == available) {
        printf("dimensions ok\n");
    }
}

void
btrfs_io_prepend_string(char *buffer, char *desc, char *val) {
    strcat(buffer, desc);
    strcat(buffer, ": ");
    strcat(buffer, val);
}

void
btrfs_io_prepend_uint64_t(char *buffer, char *desc, uint64_t val) {
    strcat(buffer, desc);
    strcat(buffer, ": ");
    char tmp[32] = "";
    btrfs_io_print_uint64_t(tmp, val);
    strcat(buffer, tmp);
}

void
btrfs_io_print_uint8_t(char *buffer, uint8_t val) {
    sprintf(buffer, "%" PRIu8, val);
}

void
btrfs_io_print_uint16_t(char *buffer, uint16_t val) {
    sprintf(buffer, "%" PRIu16, val);
}

void
btrfs_io_print_uint32_t(char *buffer, uint32_t val) {
    sprintf(buffer, "%" PRIu32, val);
}

void
btrfs_io_print_uint64_t(char *buffer, uint64_t val) {
    sprintf(buffer, "%" PRIu64, val);
}

ssize_t
btrfs_io_read_field(char *data, void *out, ssize_t offset,
        ssize_t field_size) {
    memcpy(out, (data + offset), field_size);
    return offset + field_size;
}

/*
 * Parse Methods
 */

ssize_t
btrfs_io_parse_chunk_item(char *data, btrfs_chunk_item * item) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&item->size_of_chunk), off, 0x8);
    off = btrfs_io_read_field(data, (&item->owner), off, 0x8);
    off = btrfs_io_read_field(data, (&item->stripe_len), off, 0x8);
    off = btrfs_io_read_field(data, (&item->type), off, 0x8);
    off = btrfs_io_read_field(data, (&item->io_align), off, 0x4);
    off = btrfs_io_read_field(data, (&item->io_width), off, 0x4);
    off = btrfs_io_read_field(data, (&item->sector_size), off, 0x4);
    off = btrfs_io_read_field(data, (&item->num_stripes), off, 0x2);
    off = btrfs_io_read_field(data, (&item->sub_stripes), off, 0x2);
    assert(off == STRUCT_CHUNK_ITEM_SIZE);
    return off;
}

ssize_t
btrfs_io_parse_chunk_item_stripe(char *data,
        btrfs_chunk_item_stripe * item) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&item->device_id), off, 0x8);
    off = btrfs_io_read_field(data, (&item->offset), off, 0x8);
    off = btrfs_io_read_field(data, (&item->uuid), off, 0x10);
    assert(off == STRUCT_CHUNK_ITEM_STRIPE_SIZE);
    return off;
}

ssize_t
btrfs_io_parse_dev_extent(char *data, btrfs_dev_extent * e) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&e->chunk_tree), off, 0x8);
    off = btrfs_io_read_field(data, (&e->chunk_oid), off, 0x8);
    off = btrfs_io_read_field(data, (&e->logical_address), off, 0x8);
    off = btrfs_io_read_field(data, (&e->size), off, 0x8);
    off = btrfs_io_read_field(data, (&e->uuid), off, 0x10);
    assert(off == STRUCT_DEV_EXTENT_SIZE);
    return off;
}

/**
 * Parse a btrfs_dev_item struct.
 * @param data
 * @param dev_item
 * @return number of bytes read.
 */
ssize_t
btrfs_io_parse_dev_item(char *data, btrfs_dev_item * dev_item) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&dev_item->dev_id), off, 0x8);
    off =
            btrfs_io_read_field(data, (&dev_item->number_of_bytes), off, 0x8);
    off =
            btrfs_io_read_field(data, (&dev_item->number_of_bytes_used), off,
            0x8);
    off =
            btrfs_io_read_field(data, (&dev_item->optimal_io_align), off, 0x4);
    off =
            btrfs_io_read_field(data, (&dev_item->optimal_io_width), off, 0x4);
    off =
            btrfs_io_read_field(data, (&dev_item->minimal_io_size), off, 0x4);
    off = btrfs_io_read_field(data, (&dev_item->type), off, 0x8);
    off = btrfs_io_read_field(data, (&dev_item->generation), off, 0x8);
    off = btrfs_io_read_field(data, (&dev_item->start_offset), off, 0x8);
    off = btrfs_io_read_field(data, (&dev_item->dev_group), off, 0x4);
    off = btrfs_io_read_field(data, (&dev_item->seek_speed), off, 0x1);
    off = btrfs_io_read_field(data, (&dev_item->bandwidth), off, 0x1);
    off = btrfs_io_read_field(data, (&dev_item->device_uuid), off, 0x10);
    off =
            btrfs_io_read_field(data, (&dev_item->filesystem_uuid), off, 0x10);
    assert(off == STRUCT_DEV_ITEM_SIZE);
    return off;
}

ssize_t
btrfs_io_parse_dir_index(char *data, btrfs_dir_index * d) {
    ssize_t off = 0;
    off += btrfs_io_parse_key(data, (&d->location_of_child));
    off = btrfs_io_read_field(data, (&d->transid), off, 0x8);
    off = btrfs_io_read_field(data, (&d->m), off, 0x2);
    off = btrfs_io_read_field(data, (&d->n), off, 0x2);
    off = btrfs_io_read_field(data, (&d->type), off, 0x1);
    int data_size = d->m + d->n;
    char *data_ptr = tsk_malloc(data_size);
    off = btrfs_io_read_field(data, data_ptr, off, data_size);
    d->data = data_ptr;
    return off;
}

ssize_t
btrfs_io_parse_extent_data(char *data, btrfs_extent_data * d) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&d->generation), off, 0x8);
    off =
            btrfs_io_read_field(data, (&d->size_of_decoded_extent), off, 0x8);
    off = btrfs_io_read_field(data, (&d->compression), off, 0x1);
    off = btrfs_io_read_field(data, (&d->encryption), off, 0x1);
    off = btrfs_io_read_field(data, (&d->other_encoding), off, 0x2);
    off = btrfs_io_read_field(data, (&d->type), off, 0x1);
    if (d->type != 0) {
        off =
                btrfs_io_read_field(data, (&d->extent_logical_address), off,
                0x8);
        off = btrfs_io_read_field(data, (&d->extent_size), off, 0x8);
        off = btrfs_io_read_field(data, (&d->extent_offset), off, 0x8);
        off =
                btrfs_io_read_field(data, (&d->logical_bytes_file), off, 0x8);
    } else if (d->type == 0) {
        // Inline data
        size_t inline_size = d->size_of_decoded_extent;
        char *inline_data = tsk_malloc(inline_size);
        off = btrfs_io_read_field(data, inline_data, off, inline_size);
        d->inline_data = inline_data;
    }
    return off;
}

ssize_t
btrfs_io_parse_extent_data_ref(char *data, btrfs_extent_data_ref * e) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&e->root_objectid), off, 0x8);
    off = btrfs_io_read_field(data, (&e->object_id_owner), off, 0x8);
    off = btrfs_io_read_field(data, (&e->offset), off, 0x8);
    off = btrfs_io_read_field(data, (&e->count), off, 0x4);
    return off;
}

ssize_t
btrfs_io_parse_extent_item(char *data, btrfs_extent_item * i) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&i->refcount), off, 0x8);
    off = btrfs_io_read_field(data, (&i->generation), off, 0x8);
    off = btrfs_io_read_field(data, (&i->flags), off, 0x8);
    if (i->flags == EXTENT_ITEM_TREE_BLOCK) {
        // TREE BLOCK
        off += btrfs_io_parse_key((data + off), (&i->key));
        off = btrfs_io_read_field(data, (&i->level), off, 0x1);
    } else if (i->flags == EXTENT_ITEM_DATA) {
        // read the inline refs.
        i->inline_refs =
                tsk_malloc(i->refcount * sizeof (btrfs_extent_item_inline_ref));
        int j;
        for (j = 0; j < i->refcount; j++) {
            btrfs_extent_item_inline_ref inlref;
            uint8_t type;
            off = btrfs_io_read_field(data, &type, off, 0x1);
            if (type == INLINE_EXTENT_DATA_REF) {
                off =
                        btrfs_io_read_field(data, (&inlref.data), off,
                        STRUCT_EXTENT_DATA_REF_SIZE);
            }
        }
    }
    return off;
}

ssize_t
btrfs_io_parse_header(char *data, btrfs_header * header) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&header->checksum), off, 0x20);
    off = btrfs_io_read_field(data, (&header->uuid), off, 0x10);
    off = btrfs_io_read_field(data, (&header->logical_address), off, 0x8);
    off = btrfs_io_read_field(data, (&header->flags), off, 0x7);
    off = btrfs_io_read_field(data, (&header->backref), off, 0x1);
    off = btrfs_io_read_field(data, (&header->chunk_tree_uuid), off, 0x10);
    off = btrfs_io_read_field(data, (&header->generation), off, 0x8);
    off = btrfs_io_read_field(data, (&header->tree_id), off, 0x8);
    off = btrfs_io_read_field(data, (&header->number_items), off, 0x4);
    off = btrfs_io_read_field(data, (&header->level), off, 0x1);
    assert(off == STRUCT_HEADER_SIZE);
    return off;
}

ssize_t
btrfs_io_parse_inode_item(char *data, btrfs_inode_item * inode) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&inode->generation), off, 0x8);
    off = btrfs_io_read_field(data, (&inode->transid), off, 0x8);
    off = btrfs_io_read_field(data, (&inode->st_size), off, 0x8);
    off = btrfs_io_read_field(data, (&inode->st_blocks), off, 0x8);
    off = btrfs_io_read_field(data, (&inode->block_group), off, 0x8);
    off = btrfs_io_read_field(data, (&inode->st_nlink), off, 0x4);
    off = btrfs_io_read_field(data, (&inode->st_uid), off, 0x4);
    off = btrfs_io_read_field(data, (&inode->st_gid), off, 0x4);
    off = btrfs_io_read_field(data, (&inode->st_mode), off, 0x4);
    off = btrfs_io_read_field(data, (&inode->st_rdev), off, 0x8);
    off = btrfs_io_read_field(data, (&inode->flags), off, 0x8);
    off = btrfs_io_read_field(data, (&inode->sequence), off, 0x8);
    off = btrfs_io_read_field(data, (&inode->reserved), off, 0x20);
    off += btrfs_io_parse_time((data + off), (&inode->st_Atime));
    off += btrfs_io_parse_time((data + off), (&inode->st_Ctime));
    off += btrfs_io_parse_time((data + off), (&inode->st_Mtime));
    off += btrfs_io_parse_time((data + off), (&inode->otime));
    assert(off == STRUCT_INODE_ITEM_SIZE);
    return off;
}

ssize_t
btrfs_io_parse_inode_ref(char *data, btrfs_inode_ref * inode) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&inode->dir_index), off, 0x8);
    off = btrfs_io_read_field(data, (&inode->name_length), off, 0x2);
    char *name = tsk_malloc(inode->name_length);
    inode->name = name;
    off = btrfs_io_read_field(data, name, off, inode->name_length);
    return off;
}

ssize_t
btrfs_io_parse_item(char *data, btrfs_item * item) {
    ssize_t off = 0;
    off = btrfs_io_parse_key(data, (&item->key));
    off = btrfs_io_read_field(data, (&item->data_offset), off, 0x4);
    off = btrfs_io_read_field(data, (&item->data_size), off, 0x4);
    assert(off == STRUCT_ITEM_SIZE);
    return off;
}

ssize_t
btrfs_io_parse_key(char *data, btrfs_key * key) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&key->object_id), off, 0x8);
    off = btrfs_io_read_field(data, (&key->item_type), off, 0x1);
    off = btrfs_io_read_field(data, (&key->offset), off, 0x8);
    assert(off == STRUCT_KEY_SIZE);
    return off;
}

ssize_t
btrfs_io_parse_block_ptr(char *data, btrfs_block_ptr * kp) {
    ssize_t off = 0;
    off = btrfs_io_parse_key(data, (&kp->key));
    off = btrfs_io_read_field(data, (&kp->block_number), off, 0x8);
    off = btrfs_io_read_field(data, (&kp->generation), off, 0x8);
    assert(off == STRUCT_BLOCK_PTR_SIZE);
    return off;
}

ssize_t
btrfs_io_parse_root_item(char *data, btrfs_root_item * r) {
    ssize_t off = 0;
    off += btrfs_io_parse_inode_item(data, (&r->inode_item));
    off = btrfs_io_read_field(data, (&r->expected_generation), off, 0x8);
    off = btrfs_io_read_field(data, (&r->object_id), off, 0x8);
    off =
            btrfs_io_read_field(data, (&r->block_number_root_node), off, 0x8);
    off = btrfs_io_read_field(data, (&r->byte_limit), off, 0x8);
    off = btrfs_io_read_field(data, (&r->bytes_used), off, 0x8);
    off =
            btrfs_io_read_field(data, (&r->last_generation_snapshot), off,
            0x8);
    off = btrfs_io_read_field(data, (&r->flags), off, 0x8);
    off = btrfs_io_read_field(data, (&r->nr_references), off, 0x4);
    off += btrfs_io_parse_key((data + off), (&r->drop_progress));
    off = btrfs_io_read_field(data, (&r->drop_level), off, 0x1);
    off = btrfs_io_read_field(data, (&r->root_tree_level), off, 0x1);
    assert(off == STRUCT_ROOT_ITEM_SIZE);
    return off;
}

/**
 * Read the superblock struct.
 * @param data The pointer to the char data of the superblock.
 * @param superblock The pointer to the allocated superblock struct. Sub-structs
 * need to be allocated too!
 * @return number of bytes read.
 */
ssize_t
btrfs_io_parse_superblock(char *data, btrfs_superblock * superblock) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&superblock->checksum), off, 0x20);
    off = btrfs_io_read_field(data, (&superblock->uuid), off, 0x10);
    off =
            btrfs_io_read_field(data, (&superblock->phys_addr_superblock), off,
            0x8);
    off = btrfs_io_read_field(data, (&superblock->flags), off, 0x8);
    off = btrfs_io_read_field(data, (&superblock->magic), off, 0x8);
    off = btrfs_io_read_field(data, (&superblock->generation), off, 0x8);
    off =
            btrfs_io_read_field(data, (&superblock->log_addr_root_tree_root),
            off, 0x8);
    off =
            btrfs_io_read_field(data, (&superblock->log_addr_chunk_tree_root),
            off, 0x8);
    off =
            btrfs_io_read_field(data, (&superblock->log_addr_log_tree_root),
            off, 0x8);
    off =
            btrfs_io_read_field(data, (&superblock->log_root_transid), off,
            0x8);
    off = btrfs_io_read_field(data, (&superblock->total_bytes), off, 0x8);
    off = btrfs_io_read_field(data, (&superblock->bytes_used), off, 0x8);
    off =
            btrfs_io_read_field(data, (&superblock->root_dir_objectid), off,
            0x8);
    off = btrfs_io_read_field(data, (&superblock->num_devices), off, 0x8);
    off = btrfs_io_read_field(data, (&superblock->sectorsize), off, 0x4);
    off = btrfs_io_read_field(data, (&superblock->nodesize), off, 0x4);
    off = btrfs_io_read_field(data, (&superblock->leafsize), off, 0x4);
    off = btrfs_io_read_field(data, (&superblock->stripesize), off, 0x4);
    off = btrfs_io_read_field(data, (&superblock->n), off, 0x4);
    off =
            btrfs_io_read_field(data, (&superblock->chunk_root_generation),
            off, 0x8);
    off = btrfs_io_read_field(data, (&superblock->compat_flags), off, 0x8);
    off =
            btrfs_io_read_field(data, (&superblock->compat_ro_flags), off,
            0x8);
    off =
            btrfs_io_read_field(data, (&superblock->incompat_flags), off, 0x8);
    off = btrfs_io_read_field(data, (&superblock->csum_type), off, 0x2);
    off = btrfs_io_read_field(data, (&superblock->root_level), off, 0x1);
    off =
            btrfs_io_read_field(data, (&superblock->chunk_root_level), off,
            0x1);
    off =
            btrfs_io_read_field(data, (&superblock->log_root_level), off, 0x1);
    off += btrfs_io_parse_dev_item((data + off), (&superblock->dev_item));
    off = btrfs_io_read_field(data, (&superblock->label), off, 0x100);
    off = btrfs_io_read_field(data, (&superblock->reserved), off, 0x100);
    off = btrfs_io_read_field(data, (&superblock->bootstrap_chunks), off,
            0x800);
    off = btrfs_io_read_field(data, (&superblock->unused), off, 0x4d5);
    assert(off == STRUCT_SUPERBLOCK_SIZE);
    return off;
}

ssize_t
btrfs_io_parse_time(char *data, btrfs_time * time) {
    ssize_t off = 0;
    off = btrfs_io_read_field(data, (&time->epoch_seconds), off, 0x8);
    off = btrfs_io_read_field(data, (&time->nanoseconds), off, 0x4);
    return off;
}

/*
 * Print Methods
 */

void
btrfs_io_print_checksum(char *buffer, char **checksum) {
    char tmp[2] = "";
    char result[128] = "";
    int i;
    for (i = 0; i < 0x20; i++) {
        sprintf(tmp, "%02x", checksum[i]);
        strcat(result, tmp);
    }
    strcpy(buffer, result);
}

void
btrfs_io_print_chunk_item(char *buffer, btrfs_chunk_item * c) {
    strcpy(buffer, "CHUNK_ITEM<");
    btrfs_io_prepend_uint64_t(buffer, "size_of_chunk", c->size_of_chunk);
    btrfs_io_append_uint64_t(buffer, "owner", c->owner);
    btrfs_io_append_uint64_t(buffer, "stripe_len", c->stripe_len);
    btrfs_io_append_uint64_t(buffer, "type", c->type);
    strcat(buffer, " (");
    btrfs_io_print_chunk_type(buffer, c->type);
    strcat(buffer, ")");
    btrfs_io_append_uint32_t(buffer, "io_align", c->io_align);
    btrfs_io_append_uint32_t(buffer, "io_width", c->io_width);
    btrfs_io_append_uint32_t(buffer, "sector_size", c->sector_size);
    btrfs_io_append_uint16_t(buffer, "num_stripes", c->num_stripes);
    btrfs_io_append_uint16_t(buffer, "sub_stripes", c->sub_stripes);
    strcat(buffer, ">");
}

void
btrfs_io_print_chunk_item_stripe(char *buffer, btrfs_chunk_item_stripe * c) {
    strcpy(buffer, "CHUNK_ITEM_STRIPE<");
    btrfs_io_prepend_uint64_t(buffer, "device_id", c->device_id);
    btrfs_io_append_uint64_t(buffer, "offset", c->offset);
    strcat(buffer, ">");
}

void
btrfs_io_print_dev_extent(char *buffer, btrfs_dev_extent * e) {
    strcpy(buffer, "DEV_EXTENT<");
    btrfs_io_prepend_uint64_t(buffer, "chunk_tree_id", e->chunk_tree);
    btrfs_io_append_uint64_t(buffer, "chunk_oid", e->chunk_oid);
    btrfs_io_append_uint64_t(buffer, "logical_address",
            e->logical_address);
    btrfs_io_append_uint64_t(buffer, "size (bytes)", e->size);
    strcat(buffer, ">");
}

void
btrfs_io_print_dir_index(char *buffer, btrfs_dir_index * i) {
    char tmp[1024] = "";
    strcpy(buffer, "DIR_INDEX<");
    btrfs_io_print_key(tmp, (&i->location_of_child));
    btrfs_io_prepend_string(buffer, "location_of_child", tmp);
    btrfs_io_append_uint64_t(buffer, "transid", i->transid);
    btrfs_io_append_uint16_t(buffer, "m", i->m);
    btrfs_io_append_uint16_t(buffer, "n", i->n);
    btrfs_io_append_uint8_t(buffer, "type", i->type);
    strcat(buffer, ">");
}

void
btrfs_io_print_extent_data_ref(char *buffer, btrfs_extent_data_ref * e) {
    strcpy(buffer, "EXTENT_DATA_REF<");
    btrfs_io_prepend_uint64_t(buffer,
            "root object id (id of the tree contained in)", e->root_objectid);
    btrfs_io_append_uint64_t(buffer, "object id owner",
            e->object_id_owner);
    btrfs_io_append_uint64_t(buffer, "offset", e->offset);
    btrfs_io_append_uint32_t(buffer, "count (always 1?)", e->count);
    strcat(buffer, ">");
}

void
btrfs_io_print_extent_data(char *buffer, btrfs_extent_data * d) {
    strcpy(buffer, "EXTENT_DATA<");
    btrfs_io_prepend_uint64_t(buffer, "generation", d->generation);
    btrfs_io_append_uint64_t(buffer, "size_of_decoded_extent",
            d->size_of_decoded_extent);
    btrfs_io_append_uint8_t(buffer, "compression", d->compression);
    btrfs_io_append_uint8_t(buffer, "encryption", d->encryption);
    btrfs_io_append_uint16_t(buffer, "other_encoding", d->other_encoding);
    btrfs_io_append_uint8_t(buffer, "type", d->type);
    if (d->type != 0) {
        btrfs_io_append_uint64_t(buffer, "extent_logical_address",
                d->extent_logical_address);
        btrfs_io_append_uint64_t(buffer, "extent_size", d->extent_size);
        btrfs_io_append_uint64_t(buffer, "extent_offset",
                d->extent_offset);
        btrfs_io_append_uint64_t(buffer, "logical_bytes_file",
                d->logical_bytes_file);
    }
    strcat(buffer, ">");
}

void
btrfs_io_print_extent_item(char *buffer, btrfs_extent_item * i) {
    char tmp[1024] = "";
    strcpy(buffer, "EXTENT_ITEM<");
    btrfs_io_prepend_uint64_t(buffer, "reference count", i->refcount);
    btrfs_io_append_uint64_t(buffer, "generation", i->generation);
    btrfs_io_append_uint64_t(buffer, "flags", i->flags);
    if (i->flags == 2) {
        // TREE BLOCK
        btrfs_io_print_key(tmp, (&i->key));
        btrfs_io_append_string(buffer, "key", tmp);
        btrfs_io_append_uint8_t(buffer, "level", i->level);
    }
    strcat(buffer, ">");
}

void
btrfs_io_print_header(char *buffer, btrfs_header * h) {
    strcpy(buffer, "HEADER<");
    btrfs_io_prepend_uint64_t(buffer, "logical_address",
            h->logical_address);
    btrfs_io_append_uint8_t(buffer, "backref", h->backref);
    btrfs_io_append_uint64_t(buffer, "generation", h->generation);
    btrfs_io_append_uint64_t(buffer, "tree_id", h->tree_id);
    btrfs_io_append_uint32_t(buffer, "number_items", h->number_items);
    btrfs_io_append_uint8_t(buffer, "level", h->level);
    strcat(buffer, ">");
}

void
btrfs_io_print_inode_item(char *buffer, btrfs_inode_item * i) {
    strcpy(buffer, "INODE_ITEM<");
    btrfs_io_prepend_uint64_t(buffer, "generation", i->generation);
    btrfs_io_append_uint64_t(buffer, "transid", i->transid);
    btrfs_io_append_uint64_t(buffer, "st_size", i->st_size);
    btrfs_io_append_uint64_t(buffer, "st_blocks", i->st_blocks);
    btrfs_io_append_uint32_t(buffer, "st_nlink", i->st_nlink);
    btrfs_io_append_uint32_t(buffer, "st_uid", i->st_uid);
    btrfs_io_append_uint32_t(buffer, "st_gid", i->st_gid);
    btrfs_io_append_uint32_t(buffer, "st_mode", i->st_mode);
    strcat(buffer, ">");
}

void
btrfs_io_print_item(char *buffer, btrfs_item * i) {
    char tmp[256] = "";
    strcpy(buffer, "ITEM<");
    btrfs_io_print_key(tmp, (&i->key));
    btrfs_io_prepend_string(buffer, "key", tmp);
    btrfs_io_append_uint32_t(buffer, "data_offset", i->data_offset);
    btrfs_io_append_uint32_t(buffer, "data_size", i->data_size);
    strcat(buffer, ">");
}

void
btrfs_io_print_chunk_type(char *buffer, uint64_t type) {
    if ((type & CHUNK_TYPE_DATA) == CHUNK_TYPE_DATA) {
        strcat(buffer, "DATA");
    }
    if ((type & CHUNK_TYPE_SYSTEM) == CHUNK_TYPE_SYSTEM) {
        strcat(buffer, "SYSTEM");
    }
    if ((type & CHUNK_TYPE_METADATA) == CHUNK_TYPE_METADATA) {
        strcat(buffer, "METADATA");
    }
    if ((type & CHUNK_TYPE_RAID0) == CHUNK_TYPE_RAID0) {
        strcat(buffer, "RAID0");
    }
    if ((type & CHUNK_TYPE_RAID1) == CHUNK_TYPE_RAID1) {
        strcat(buffer, ",RAID1");
    }
    if ((type & CHUNK_TYPE_MIRRORED) == CHUNK_TYPE_MIRRORED) {
        strcat(buffer, ",MIRRORED");
    }
    if ((type & CHUNK_TYPE_RAID10) == CHUNK_TYPE_RAID10) {
        strcat(buffer, ",RAID10");
    }
}

void
btrfs_io_print_item_type(char *buffer, uint8_t item_type) {
    switch (item_type) {
        case ITEM_TYPE_BLOCK_GROUP_ITEM:
            strcat(buffer, "BLOCK_GROUP_ITEM");
            break;
        case ITEM_TYPE_CHUNK_ITEM:
            strcat(buffer, "CHUNK_ITEM");
            break;
        case ITEM_TYPE_DEV_EXTENT:
            strcat(buffer, "DEV_EXTENT");
            break;
        case ITEM_TYPE_DEV_ITEM:
            strcat(buffer, "DEV_ITEM");
            break;
        case ITEM_TYPE_DIR_INDEX:
            strcat(buffer, "DIR_INDEX");
            break;
        case ITEM_TYPE_DIR_ITEM:
            strcat(buffer, "DIR_ITEM");
            break;
        case ITEM_TYPE_DIR_LOG_INDEX:
            strcat(buffer, "DIR_LOG_INDEX");
            break;
        case ITEM_TYPE_DIR_LOG_ITEM:
            strcat(buffer, "DIR_LOG_ITEM");
            break;
        case ITEM_TYPE_EXTENT_CSUM:
            strcat(buffer, "EXTENT_CSUM");
            break;
        case ITEM_TYPE_EXTENT_DATA:
            strcat(buffer, "EXTENT_DATA");
            break;
        case ITEM_TYPE_EXTENT_DATA_REF:
            strcat(buffer, "EXTENT_DATA_REF");
            break;
        case ITEM_TYPE_EXTENT_ITEM:
            strcat(buffer, "EXTENT_ITEM");
            break;
        case ITEM_TYPE_EXTENT_REF_V0:
            strcat(buffer, "EXTENT_REF_V0");
            break;
        case ITEM_TYPE_INODE_ITEM:
            strcat(buffer, "INODE_ITEM");
            break;
        case ITEM_TYPE_INODE_REF:
            strcat(buffer, "INODE_REF");
            break;
        case ITEM_TYPE_ORPHAN_ITEM:
            strcat(buffer, "ORPHAN_ITEM");
            break;
        case ITEM_TYPE_ROOT_ITEM:
            strcat(buffer, "ROOT_ITEM");
            break;
        case ITEM_TYPE_SHARED_BLOCK_REF:
            strcat(buffer, "SHARED_BLOCK_REF");
            break;
        case ITEM_TYPE_SHARED_DATA_REF:
            strcat(buffer, "SHARED_DATA_REF");
            break;
        case ITEM_TYPE_STRING_ITEM:
            strcat(buffer, "STRING_ITEM");
            break;
        case ITEM_TYPE_TREE_BLOCK_REF:
            strcat(buffer, "TREE_BLOCK_REF");
            break;
        case ITEM_TYPE_XATTR_ITEM:
            strcat(buffer, "XATTR_ITEM");
            break;
        default:
            strcat(buffer, "UNKNOWN_ITEM_TYPE");
            break;
    }
}

void
btrfs_io_print_key(char *buffer, btrfs_key * k) {
    strcpy(buffer, "KEY<");
    btrfs_io_prepend_uint64_t(buffer, "object_id", k->object_id);
    btrfs_io_append_uint8_t(buffer, "item_type", k->item_type);
    strcat(buffer, " (");
    btrfs_io_print_item_type(buffer, k->item_type);
    strcat(buffer, ")");
    btrfs_io_append_uint64_t(buffer, "offset", k->offset);
    strcat(buffer, ">");
}

void
btrfs_io_print_root_item(char *buffer, btrfs_root_item * r) {
    char tmp[2048] = "";
    strcpy(buffer, "ROOT_ITEM<");
    btrfs_io_print_inode_item(tmp, &r->inode_item);
    btrfs_io_prepend_string(buffer, "inode_item", tmp);
    btrfs_io_append_uint64_t(buffer, "expected_generation",
            r->expected_generation);
    btrfs_io_append_uint64_t(buffer, "object_id (root dir id)",
            r->object_id);
    btrfs_io_append_uint64_t(buffer, "blk_nr_root_node",
            r->block_number_root_node);
    strcat(buffer, ">");
}

void
btrfs_io_print_uuid(char *buffer, char **uuid) {
    char tmp[2] = "";
    char result[128] = "";
    int i;
    for (i = 0; i < 0x10; i++) {
        sprintf(tmp, "%c", uuid[i]);
        strcat(result, tmp);
    }
    strcpy(buffer, result);
}

/*
 * Read Methods.
 */

btrfs_block_ptr
btrfs_io_read_block_ptr_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address) {
    uint64_t physical_address = btrfs_resolve_logical_address(btrfs_info,
            logical_address);

    return btrfs_io_read_block_ptr_pa(btrfs_info, physical_address);
}

btrfs_block_ptr
btrfs_io_read_block_ptr_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address) {
    // Read the data from disk
    const ssize_t s = STRUCT_BLOCK_PTR_SIZE;
    char data[s];
    tsk_fs_read(&(btrfs_info->fs_info), physical_address, data, s);

    // Parse it
    btrfs_block_ptr kp;
    btrfs_io_parse_block_ptr(data, &kp);

    return kp;
}

btrfs_dev_extent
btrfs_io_read_dev_extent_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address) {
    uint64_t physical_address = btrfs_resolve_logical_address(btrfs_info,
            logical_address);

    return btrfs_io_read_dev_extent_pa(btrfs_info, physical_address);
}

btrfs_dev_extent
btrfs_io_read_dev_extent_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address) {
    // Read the data from disk
    const ssize_t s = STRUCT_DEV_EXTENT_SIZE;
    char data[s];
    tsk_fs_read(&(btrfs_info->fs_info), physical_address, data, s);

    // Parse it
    btrfs_dev_extent d;
    btrfs_io_parse_dev_extent(data, &d);

    return d;
}

btrfs_dir_index
btrfs_io_read_dir_index_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address, ssize_t size) {
    uint64_t physical_address = btrfs_resolve_logical_address(btrfs_info,
            logical_address);

    return btrfs_io_read_dir_index_pa(btrfs_info, physical_address, size);
}

btrfs_dir_index
btrfs_io_read_dir_index_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address, ssize_t size) {
    // Read the data from disk
    char data[size];
    tsk_fs_read(&(btrfs_info->fs_info), physical_address, data, size);

    // Parse it
    btrfs_dir_index d;
    btrfs_io_parse_dir_index(data, &d);

    return d;
}

btrfs_extent_data
btrfs_io_read_extent_data_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address, uint32_t size) {
    uint64_t physical_address = btrfs_resolve_logical_address(btrfs_info,
            logical_address);

    return btrfs_io_read_extent_data_pa(btrfs_info, physical_address,
            size);
}

btrfs_extent_data
btrfs_io_read_extent_data_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address, uint32_t size) {
    // Read the data from disk
    char data[size];
    tsk_fs_read(&(btrfs_info->fs_info), physical_address, data, size);

    // Parse it
    btrfs_extent_data d;
    btrfs_io_parse_extent_data(data, &d);

    return d;
}

btrfs_extent_item
btrfs_io_read_extent_item_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address, uint32_t size) {
    uint64_t physical_address = btrfs_resolve_logical_address(btrfs_info,
            logical_address);

    return btrfs_io_read_extent_item_pa(btrfs_info, physical_address,
            size);
}

btrfs_extent_item
btrfs_io_read_extent_item_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address, uint32_t size) {
    // Read the data from disk
    char *data = tsk_malloc(size);
    if (tsk_fs_read(&(btrfs_info->fs_info), physical_address, data,
            size) != size) {
        printf("read wrong number of bytes!!!");
    }

    // Parse it
    btrfs_extent_item d = {};
    btrfs_io_parse_extent_item(data, &d);
    free(data);

    return d;
}

/**
 * Reads a btrfs_header from disk.
 * @param fs
 * @param logical_address The logical address of the header.
 * @return
 */
btrfs_header
btrfs_io_read_header_la(BTRFS_INFO * btrfs_info, uint64_t logical_address) {
    uint64_t physical_address = btrfs_resolve_logical_address(btrfs_info,
            logical_address);

    return btrfs_io_read_header_pa(btrfs_info, physical_address);
}

/**
 * Reads a btrfs_header from disk.
 * @param fs
 * @param physical_address The physical address of the header.
 * @return
 */
btrfs_header
btrfs_io_read_header_pa(BTRFS_INFO * btrfs_info, uint64_t physical_address) {
    // Read the data from disk
    const ssize_t s = STRUCT_HEADER_SIZE;
    char data[s];
    tsk_fs_read(&(btrfs_info->fs_info), physical_address, data, s);

    // Parse it
    btrfs_header header;
    btrfs_io_parse_header(data, &header);

    return header;
}

btrfs_inode_item
btrfs_io_read_inode_item_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address) {
    uint64_t physical_address = btrfs_resolve_logical_address(btrfs_info,
            logical_address);

    return btrfs_io_read_inode_item_pa(btrfs_info, physical_address);
}

btrfs_inode_item
btrfs_io_read_inode_item_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address) {
    // Read the data from disk
    const ssize_t s = STRUCT_INODE_ITEM_SIZE;
    char data[s];
    tsk_fs_read(&(btrfs_info->fs_info), physical_address, data, s);

    // Parse it
    btrfs_inode_item item;
    btrfs_io_parse_inode_item(data, &item);

    return item;
}

/**
 * Reads a btrfs_item from disk.
 * @param fs
 * @param logical_address The logical address of the item.
 * @return
 */
btrfs_item
btrfs_io_read_item_la(BTRFS_INFO * btrfs_info, uint64_t logical_address) {
    uint64_t physical_address = btrfs_resolve_logical_address(btrfs_info,
            logical_address);

    return btrfs_io_read_item_pa(btrfs_info, physical_address);
}

/**
 * Reads a btrfs_item from disk.
 * @param fs
 * @param physical_address The physical address of the item.
 * @return
 */
btrfs_item
btrfs_io_read_item_pa(BTRFS_INFO * btrfs_info, uint64_t physical_address) {
    // Read the data from disk
    const ssize_t s = STRUCT_ITEM_SIZE;
    char data[s];
    tsk_fs_read(&(btrfs_info->fs_info), physical_address, data, s);

    // Parse it
    btrfs_item item;
    btrfs_io_parse_item(data, &item);

    return item;
}

btrfs_key
btrfs_io_read_key_la(BTRFS_INFO * btrfs_info, uint64_t logical_address) {
    uint64_t physical_address = btrfs_resolve_logical_address(btrfs_info,
            logical_address);

    return btrfs_io_read_key_pa(btrfs_info, physical_address);
}

btrfs_key
btrfs_io_read_key_pa(BTRFS_INFO * btrfs_info, uint64_t physical_address) {
    // Read the data from disk
    const ssize_t s = STRUCT_KEY_SIZE;
    char data[s];
    tsk_fs_read(&(btrfs_info->fs_info), physical_address, data, s);

    // Parse it
    btrfs_key k;
    btrfs_io_parse_key(data, &k);

    return k;
}

btrfs_root_item
btrfs_io_read_root_item_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address) {
    uint64_t physical_address = btrfs_resolve_logical_address(btrfs_info,
            logical_address);

    return btrfs_io_read_root_item_pa(btrfs_info, physical_address);
}

btrfs_root_item
btrfs_io_read_root_item_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address) {
    // Read the data from disk
    const ssize_t s = STRUCT_ROOT_ITEM_SIZE;
    char data[s];
    tsk_fs_read(&(btrfs_info->fs_info), physical_address, data, s);

    // Parse it
    btrfs_root_item r;
    btrfs_io_parse_root_item(data, &r);

    return r;
}

btrfs_superblock *
btrfs_io_read_superblock_pa(TSK_FS_INFO * fs, uint64_t physical_addresss) {
    // Read the data from disk
    ssize_t s = STRUCT_SUPERBLOCK_SIZE;
    char data[s];
    tsk_fs_read(fs, physical_addresss, data, s);

    // Parse it
    btrfs_superblock *sb = tsk_malloc(sizeof (btrfs_superblock));
    btrfs_io_parse_superblock(data, sb);

    return sb;
}
