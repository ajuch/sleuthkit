/*
 ** tsk_btrfs.h
 ** The  Sleuth Kit
 **
 ** Header file of the Btrfs TSK implementation.
 **
 ** Andreas Juch [andreas.juch@gmail.com]
 ** Copyright (c) 2013-1014 Andreas Juch
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file tsk_btrfs.h
 * Btrfs header.
 */

#include "queue.h"

#ifndef TSK_BTRFS_H_
#define TSK_BTRFS_H_

// Constants
#define BTRFS_SUPERBLOCK_LOCATION 0x10000
#define BTRFS_FS_MAGIC "_BHRfS_M"
#define BTRFS_FIRST_SUBVOLUME_ID 5
#define BTRFS_MIN_SUBVOLUME_ID 256
#define BTRFS_MAX_SUBVOLUME_ID 2048
#define BTRFS_FILE_CONTENT_LEN 0
#define BTRFS_MAX_FILE_NAME_LEN 255

// Struct sizes

typedef enum {
    STRUCT_KEY_SIZE = 0x11,
    STRUCT_UUID_SIZE = 0x10,
    STRUCT_SUPERBLOCK_SIZE = 0x1000,
    STRUCT_CHUNK_ITEM_SIZE = 0x30,
    STRUCT_CHUNK_ITEM_STRIPE_SIZE = 0x20,
    STRUCT_DEV_ITEM_SIZE = 0x62,
    STRUCT_EXTENT_DATA_SIZE_NORMAL = 0x35,
    STRUCT_EXTENT_DATA_SIZE_INLINE = 0x15,
    STRUCT_HEADER_SIZE = 0x65,
    STRUCT_ITEM_SIZE = 0x19,
    STRUCT_BLOCK_PTR_SIZE = 0x21,
    STRUCT_ROOT_ITEM_SIZE = 0xef,
    STRUCT_INODE_ITEM_SIZE = 0xa0,
    STRUCT_DEV_EXTENT_SIZE = 0x30,
    STRUCT_EXTENT_DATA_REF_SIZE = 0x1c
} struct_size_t;

// Item types

typedef enum {
    ITEM_TYPE_INODE_ITEM = 0x01,
    ITEM_TYPE_INODE_REF = 0x0c,
    ITEM_TYPE_XATTR_ITEM = 0x18,
    ITEM_TYPE_ORPHAN_ITEM = 0x30,
    ITEM_TYPE_DIR_LOG_ITEM = 0x3c,
    ITEM_TYPE_DIR_LOG_INDEX = 0x48,
    ITEM_TYPE_DIR_ITEM = 0x54,
    ITEM_TYPE_DIR_INDEX = 0x60,
    ITEM_TYPE_EXTENT_DATA = 0x6c,
    ITEM_TYPE_EXTENT_CSUM = 0x80,
    ITEM_TYPE_ROOT_ITEM = 0x84,
    ITEM_TYPE_EXTENT_ITEM = 0xa8,
    ITEM_TYPE_TREE_BLOCK_REF = 0xb0,
    ITEM_TYPE_EXTENT_DATA_REF = 0xb2,
    ITEM_TYPE_EXTENT_REF_V0 = 0xb4,
    ITEM_TYPE_SHARED_BLOCK_REF = 0xb6,
    ITEM_TYPE_SHARED_DATA_REF = 0xb8,
    ITEM_TYPE_BLOCK_GROUP_ITEM = 0xc0,
    ITEM_TYPE_DEV_EXTENT = 0xcc,
    ITEM_TYPE_DEV_ITEM = 0xd8,
    ITEM_TYPE_CHUNK_ITEM = 0xe4,
    ITEM_TYPE_STRING_ITEM = 0xdf
} item_type_t;

typedef enum {
    CHUNK_TYPE_DATA = 0x01,
    CHUNK_TYPE_SYSTEM = 0x02,
    CHUNK_TYPE_METADATA = 0x04,
    CHUNK_TYPE_RAID0 = 0x08,
    CHUNK_TYPE_RAID1 = 0x10,
    CHUNK_TYPE_MIRRORED = 0x20,
    CHUNK_TYPE_RAID10 = 0x40
} chunk_type_t;

typedef enum {
    EXTENT_ITEM_TREE_BLOCK = 0x2, EXTENT_ITEM_DATA = 0x1
} extent_item_flags;

// Tree Ids

typedef enum {
    TREE_ID_ROOT_TREE = 0x1,
    TREE_ID_EXTENT_TREE = 0x2,
    TREE_ID_CHUNK_TREE = 0x3,
    TREE_ID_DEV_TREE = 0x4,
    TREE_ID_FS_TREE = 0x5,
    TREE_ID_CHECKSUM_TREE = 0x7
} tree_id_t;

// Extent Item Inline Ref Types

typedef enum {
    INLINE_TREE_BLOCK_REF = 0xb0,
    INLINE_EXTENT_DATA_REF = 0xb2,
    INLINE_EXTENT_REF_V0 = 0xb4,
    INLINE_SHARED_BLOCK_REF = 0xb6,
    INLINE_SHARED_DATA_REF = 0xb8
} extent_item_inline_ref_types;

// Filesystem Structs

typedef struct {
    uint64_t high;
    uint64_t low;
} btrfs_uuid;

typedef struct {
    /**
     * Object ID. Each tree has its own set of Object IDs.
     * From: https://btrfs.wiki.kernel.org/index.php/On-disk_Format
     */
    uint64_t object_id;
    uint8_t item_type;
    /**
     * Offset. The meaning depends on the item type.
     * From: https://btrfs.wiki.kernel.org/index.php/On-disk_Format
     */
    uint64_t offset;
} btrfs_key;

typedef struct {
    uint64_t device_id;
    uint64_t offset;
    /**
     * Device UUID.
     */
    char uuid[0x10];
} btrfs_chunk_item_stripe;

typedef struct {
    uint64_t dev_id;
    uint64_t number_of_bytes;
    uint64_t number_of_bytes_used;
    uint32_t optimal_io_align;
    uint32_t optimal_io_width;
    uint32_t minimal_io_size;
    uint64_t type;
    uint64_t generation;
    uint64_t start_offset;
    uint32_t dev_group;
    uint8_t seek_speed;
    uint8_t bandwidth;
    btrfs_uuid device_uuid;
    btrfs_uuid filesystem_uuid;
} btrfs_dev_item;

typedef struct {
    uint64_t size_of_chunk;
    uint64_t owner;
    uint64_t stripe_len;
    uint64_t type;
    uint32_t io_align;
    uint32_t io_width;
    uint32_t sector_size;
    /**
     * for each num_stripes, there is additional information after the item!
     */
    uint16_t num_stripes;
    uint16_t sub_stripes;
} btrfs_chunk_item;

typedef struct {
    char checksum[0x20];
    char uuid[0x10];
    uint64_t phys_addr_superblock;
    uint64_t flags;
    char magic[0x8];
    uint64_t generation;
    uint64_t log_addr_root_tree_root;
    uint64_t log_addr_chunk_tree_root;
    uint64_t log_addr_log_tree_root;
    uint64_t log_root_transid;
    uint64_t total_bytes;
    uint64_t bytes_used;
    uint64_t root_dir_objectid;
    uint64_t num_devices;
    uint32_t sectorsize;
    uint32_t nodesize;
    uint32_t leafsize;
    uint32_t stripesize;
    uint32_t n;
    uint64_t chunk_root_generation;
    uint64_t compat_flags;
    uint64_t compat_ro_flags;
    uint64_t incompat_flags;
    uint16_t csum_type;
    uint8_t root_level;
    uint8_t chunk_root_level;
    uint8_t log_root_level;
    btrfs_dev_item dev_item;
    char label[0x100];
    char reserved[0x100];
    /**
     * (n bytes valid) Contains (KEY, CHUNK_ITEM) pairs for all SYSTEM chunks.
     * This is needed to bootstrap the mapping from logical addresses to
     * physical.
     * From https://btrfs.wiki.kernel.org/index.php/User:Wtachi/On-disk_Format#Superblock
     */
    char bootstrap_chunks[0x800];
    char unused[0x4d5];
} btrfs_superblock;

typedef struct {
    char checksum[0x20];
    char uuid[0x10];
    uint64_t logical_address;
    char flags[0x7];
    uint8_t backref;
    char chunk_tree_uuid[0x10];
    uint64_t generation;
    uint64_t tree_id;
    uint32_t number_items;
    uint8_t level;
} btrfs_header;

typedef struct {
    btrfs_key key;
    uint32_t data_offset;
    uint32_t data_size;
} btrfs_item;

typedef struct {
    btrfs_key key;
    /**
     * The logical address of the referenced element.
     */
    uint64_t block_number;
    uint64_t generation;
} btrfs_block_ptr;

typedef struct {
    int64_t epoch_seconds;
    uint32_t nanoseconds;
} btrfs_time;

typedef struct {
    uint64_t generation;
    /**
     * transid that last touched this
     */
    uint64_t transid;
    /**
     * for a directory this is twice the total number of characters in all the
     * entries' filenames.
     */
    uint64_t st_size;
    /**
     * but in bytes. This is the sum of the offset fields of all EXTENT_DATA
     * items for this inode. For a directory, this is 0.
     */
    uint64_t st_blocks;
    uint64_t block_group;
    /**
     * st_nlink. This is the number of INODE_REF entries for the inode. For
     * trees and other objects with no INODE_REFs, this is 1.
     */
    uint32_t st_nlink;
    /**
     * User ID
     */
    uint32_t st_uid;
    /**
     * Group ID
     */
    uint32_t st_gid;
    uint32_t st_mode;
    /**
     * The lower 20 bits are the minor number, and the higher 44 bits are the
     * major number.
     */
    uint64_t st_rdev;
    uint64_t flags;
    /**
     * for NFS compatibility.
     */
    uint64_t sequence;
    char reserved[0x20];
    btrfs_time st_Atime;
    btrfs_time st_Ctime;
    btrfs_time st_Mtime;
    /**
     * reserved
     */
    btrfs_time otime;
} btrfs_inode_item;

typedef struct {
    uint8_t found;
    btrfs_inode_item inode_item;
} btrfs_inode_item_result;

typedef struct {
    /**
     * The index of this file in the directory.
     */
    uint64_t dir_index;
    uint16_t name_length;
    char *name;
} btrfs_inode_ref;

typedef struct {
    uint8_t found;
    btrfs_key key;
    btrfs_inode_ref inode_ref;
} btrfs_inode_ref_result;

typedef struct {
    btrfs_inode_item inode_item;
    uint64_t expected_generation;
    uint64_t object_id;
    /**
     * The logical address of the root node.
     */
    uint64_t block_number_root_node;
    /**
     * always 0.
     */
    uint64_t byte_limit;
    uint64_t bytes_used;
    /**
     * The last generation a snapshot was taken.
     */
    uint64_t last_generation_snapshot;
    uint64_t flags;
    uint32_t nr_references;
    /**
     * always 0:00:0
     */
    btrfs_key drop_progress;
    /**
     * always 0
     */
    uint8_t drop_level;
    uint8_t root_tree_level;
} btrfs_root_item;

typedef struct {
    btrfs_key location_of_child;
    uint64_t transid;
    uint16_t m;
    uint16_t n;
    /**
     * 0: unknown, 1: regular file, 2: dir, 3: char dev, 4: block dev, 5: fifo, 6: socket, 7: symlink, 8: extended attributes.
     */
    uint8_t type;
    /**
     * first n bytes: name, then m bytes of data (usually none for normal dirs)
     */
    char *data;
} btrfs_dir_index;

typedef struct {
    uint8_t found;
    btrfs_dir_index dir_index;
} btrfs_dir_index_result;

typedef struct {
    uint64_t generation;
    uint64_t size_of_decoded_extent;
    /**
     * 0 = none, 1 = zlib
     */
    uint8_t compression;
    /**
     * 0 = none
     */
    uint8_t encryption;
    /**
     * 0 = none
     */
    uint16_t other_encoding;
    /**
     * 0 = inline, 1 = regular, 2 = prealloc
     * Fields after type only valid if type is inline!
     */
    uint8_t type;
    /**
     * If the address is 0, the extent is sparse and consists only of zeros!
     */
    uint64_t extent_logical_address;
    uint64_t extent_size;
    uint64_t extent_offset;
    uint64_t logical_bytes_file;
    char *inline_data;
} btrfs_extent_data;

typedef struct {
    /**
     * The object id of the tree.
     */
    uint64_t offset;
} btrfs_tree_block_ref;

typedef struct {
    /**
     * id of the tree contained in.
     */
    uint64_t root_objectid;
    uint64_t object_id_owner;
    /**
     * Offset in the file data.
     */
    uint64_t offset;
    /**
     * Always 1?
     */
    uint32_t count;
} btrfs_extent_data_ref;

typedef struct {
    /**
     * The tree ID of the chunk tree. Always 0x3.
     */
    uint64_t chunk_tree;
    /**
     * The object ID of the chunk items. Always 0x100;
     */
    uint64_t chunk_oid;
    uint64_t logical_address;
    uint64_t size;
    char uuid[0x10];
} btrfs_dev_extent;

typedef struct {
    uint8_t type;
    char data[sizeof (btrfs_extent_data_ref)]; // extent_data_ref is the biggest inline ref
}
btrfs_extent_item_inline_ref;

typedef struct {
    /**
     * Number of btrfs_extent_item_references following.
     */
    uint64_t refcount;
    uint64_t generation;
    /**
     * 1 = DATA, 2 = TREE_BLOCK
     */
    uint64_t flags;
    /**
     * Key of first entry in tree? TREE_BLOCK only
     */
    btrfs_key key;
    uint8_t level;
    /**
     * An array of inline refs. Their number is stored in refcount.
     */
    btrfs_extent_item_inline_ref *inline_refs;
} btrfs_extent_item;

// Other structs

/**
 * For storing the bootstrap data from the superblock.
 */
struct chunk_entry_s {
    btrfs_key key;
    btrfs_chunk_item chunk_item;
    TAILQ_ENTRY(chunk_entry_s)
    pointers;
    btrfs_chunk_item_stripe *chunk_item_stripes;
};

struct dev_extent_entry_s {
    btrfs_key key;
    btrfs_dev_extent dev_extent;
    TAILQ_ENTRY(dev_extent_entry_s)
    pointers;
};

/**
 * The representation of a Btrfs tree.
 */
typedef struct {
    btrfs_header header;
    uint64_t physical_address;
} btrfs_tree;

/**
 * Structure for results of Btrfs tree searches.
 */
typedef struct {
    /**
     * The key that was found during the search.
     */
    btrfs_key key;
    /**
     * The physical address of the data.
     */
    uint64_t physical_address;
    /**
     * The size of the data.
     */
    uint64_t data_size;
    /**
     * Was the data found (1) or not (0).
     */
    uint8_t found;
    /**
     * The found data.
     */
    char *data;
} btrfs_tree_search_result;

struct btrfs_tree_list_result_s {
    btrfs_key key;
    uint64_t physical_address;
    uint32_t data_size;
    TAILQ_ENTRY(btrfs_tree_list_result_s)
    pointers;
};
TAILQ_HEAD(btrfs_tree_list_result_head, btrfs_tree_list_result_s);

/**
 * Maps a virtual inode number to real inodes.
 */
typedef struct {
    /**
     * The Subvolume ID that the inode is present in.
     */
    uint64_t subvolume_id;
    /**
     * The Inode number of this inode in the subvolume.
     */
    uint64_t inode_nr;
} btrfs_inode_mapping;

/*
 * Structure of a btrfs file system handle.
 */
typedef struct {
    TSK_FS_INFO fs_info; /* super class */
    btrfs_superblock *superblock; /* super block */

    /* lock protects grp_buf, grp_num, bmap_buf, bmap_grp_num, imap_buf, imap_grp_num */
    tsk_lock_t lock;

    /* the bootstrap data for resolving logical addresses */
    TAILQ_HEAD(chunks_head, chunk_entry_s) chunks_head;
    TAILQ_HEAD(dev_extents_head, dev_extent_entry_s) dev_extents_head;

    btrfs_tree root_tree;
    btrfs_tree chunk_tree;
    btrfs_tree top_level_subvolume_fs_tree; // The first subvolume with id=5
    btrfs_tree extent_tree;
    btrfs_tree dev_tree;

    uint64_t nr_subvolumes; // The number of subvolumes.
    uint64_t *subvolume_ids; // Array of subvolume ids.
    btrfs_tree *subvolume_fsroots; // The FS root trees for all subvolumes.
    struct btrfs_tree_list_result_head *subvolume_fs_tree_lists; // array of lists

    btrfs_inode_mapping *inode_mapping;
} BTRFS_INFO;

typedef int (*compare_func) (btrfs_key *, btrfs_key *);
typedef int (*result_func) (btrfs_tree_search_result *, void *);

//btrfs.c
// tsk methods
TSK_RETVAL_ENUM btrfs_tsk_dir_open_meta(TSK_FS_INFO * a_fs,
        TSK_FS_DIR ** a_fs_dir, TSK_INUM_T a_addr);
static uint8_t btrfs_tsk_inode_lookup(TSK_FS_INFO * fs,
        TSK_FS_FILE * a_fs_file, TSK_INUM_T inum);
uint8_t btrfs_tsk_load_attrs(TSK_FS_FILE * fs_file);
TSK_FS_ATTR_TYPE_ENUM btrfs_tsk_get_default_attr_type(const TSK_FS_FILE *
        a_file);
TSK_FS_BLOCK_FLAG_ENUM btrfs_tsk_block_getflags(TSK_FS_INFO * a_fs,
        TSK_DADDR_T a_addr);
// tree methods
btrfs_tree btrfs_tree_create_def_la(BTRFS_INFO * fs,
        uint64_t logical_address);
btrfs_tree btrfs_tree_create_def_pa(BTRFS_INFO * fs,
        uint64_t physical_address);
btrfs_tree btrfs_tree_get_tree_from_root_tree(BTRFS_INFO * btrfs_info,
        int tree_id);
int btrfs_tree_list(BTRFS_INFO * btrfs_info, btrfs_tree * tree,
        struct btrfs_tree_list_result_head *list_head);
int btrfs_tree_list_filter(BTRFS_INFO * btrfs_info, btrfs_tree * tree,
        struct btrfs_tree_list_result_head *list_head, compare_func cmp,
        btrfs_key * k);
void btrfs_tree_list_print(struct btrfs_tree_list_result_head *l);
void btrfs_tree_list_result_free(struct btrfs_tree_list_result_head *l);
btrfs_tree_search_result btrfs_tree_search(BTRFS_INFO * btrfs_info,
        btrfs_key * key, btrfs_tree * tree, int verbose, compare_func cmp);
int btrfs_tree_walk(BTRFS_INFO * fs, btrfs_tree * tree, btrfs_key * key,
        compare_func cmp, int verbose, result_func res, void *res_ptr);
// chunk methods
void btrfs_chunk_read_tree(BTRFS_INFO * btrfs_info, btrfs_tree * ct);
void btrfs_chunk_print_entries(BTRFS_INFO * btrfs_info);
ssize_t btrfs_chunk_add(BTRFS_INFO * btrfs_info, btrfs_key k, char *data);
// subvolume methods
btrfs_tree btrfs_subvolume_get_by_id(BTRFS_INFO * btrfs_info, uint64_t id);
void btrfs_subvolume_init(BTRFS_INFO * btrfs_info);
int btrfs_subvolume_is_id(uint64_t id);
// inode methods
uint64_t btrfs_inode_count(BTRFS_INFO * btrfs_info);
void btrfs_inode_create_mapping(BTRFS_INFO * btrfs_info);
btrfs_inode_mapping *btrfs_inode_resolve(BTRFS_INFO * btrfs_info,
        uint64_t virtual_inode_nr);
uint64_t btrfs_inode_resolve_reverse(BTRFS_INFO * btrfs_info,
        btrfs_inode_mapping * map);
// compare functions
int btrfs_cmp_func_extent_tree(btrfs_key * k1, btrfs_key * k2);
int btrfs_cmp_func_exact(btrfs_key * k1, btrfs_key * k2);
int btrfs_cmp_func_exact_ignore_offset(btrfs_key * k1, btrfs_key * k2);
int btrfs_cmp_func_match_all(btrfs_key * k1, btrfs_key * k2);
// result functions
int btrfs_tree_result_func_single(btrfs_tree_search_result * res,
        void *result_ptr);
int btrfs_tree_result_func_list(btrfs_tree_search_result * res,
        void *result_ptr);
// btrfs_find functions
btrfs_inode_item_result btrfs_find_inode_item(BTRFS_INFO * info,
        btrfs_tree * fstree, uint64_t inode_number);
btrfs_inode_ref_result btrfs_find_inode_ref(BTRFS_INFO * btrfs_info,
        btrfs_tree * fstree, uint64_t real_inode, uint64_t parent_dir_index);
// others
void btrfs_read_dev_tree(BTRFS_INFO * btrfs_info);
void btrfs_subvolume_init(BTRFS_INFO * btrfs_info);
btrfs_tree *btrfs_get_fs_root(TSK_FS_INFO * fs, uint64_t subvolume_id);
int btrfs_read_metadata(BTRFS_INFO * btrfs_info, btrfs_inode_item * ii,
        btrfs_dir_index * di, uint64_t virtual_inode, TSK_FS_META * meta);
uint64_t btrfs_resolve_logical_address_chunk_tree(TSK_FS_INFO * fs,
        uint64_t logical_address);
uint64_t btrfs_resolve_logical_address(BTRFS_INFO * btrfs_info,
        uint64_t logical_address);
btrfs_key btrfs_create_key(uint64_t object_id, uint8_t item_type,
        uint64_t offset);
TSK_FS_META_TYPE_ENUM btrfs_get_fs_meta_type(uint8_t dir_item_type);
TSK_FS_NAME_TYPE_ENUM btrfs_get_fs_name_type(uint8_t dir_item_type);
TSK_FS_ATTR_RUN *btrfs_convert_extent_data_to_data_run(BTRFS_INFO *
        btrfs_info, btrfs_extent_data * ed, uint64_t offset);

//btrfs_io.c
// helper methods
void btrfs_io_append_uint8_t(char *buffer, char *desc, uint8_t val);
void btrfs_io_append_uint64_t(char *buffer, char *desc, uint64_t val);
void btrfs_io_prepend_uint64_t(char *buffer, char *desc, uint64_t val);
// parse methods
ssize_t btrfs_io_parse_chunk_item(char *data, btrfs_chunk_item * item);
ssize_t btrfs_io_parse_chunk_item_stripe(char *data,
        btrfs_chunk_item_stripe * item);
void btrfs_io_print_chunk_type(char *buffer, uint64_t type);
ssize_t btrfs_io_parse_dev_item(char *data, btrfs_dev_item * dev_item);
ssize_t btrfs_io_parse_dir_index(char *data, btrfs_dir_index * d);
ssize_t btrfs_io_parse_extent_data(char *data, btrfs_extent_data * d);
ssize_t btrfs_io_parse_extent_item(char *data, btrfs_extent_item * i);
ssize_t btrfs_io_parse_header(char *data, btrfs_header * header);
ssize_t btrfs_io_parse_item(char *data, btrfs_item * item);
ssize_t btrfs_io_parse_inode_item(char *data, btrfs_inode_item * inode);
ssize_t btrfs_io_parse_inode_ref(char *data, btrfs_inode_ref * inode);
ssize_t btrfs_io_parse_key(char *data, btrfs_key * key);
ssize_t btrfs_io_parse_block_ptr(char *data, btrfs_block_ptr * kp);
ssize_t btrfs_io_parse_root_item(char *data, btrfs_root_item * r);
ssize_t btrfs_io_parse_superblock(char *data,
        btrfs_superblock * superblock);
ssize_t btrfs_io_parse_time(char *data, btrfs_time * time);
// print methods
void btrfs_io_print_uint8_t(char *buffer, uint8_t val);
void btrfs_io_print_uint16_t(char *buffer, uint16_t val);
void btrfs_io_print_uint32_t(char *buffer, uint32_t val);
void btrfs_io_print_uint64_t(char *buffer, uint64_t val);
void btrfs_io_print_chunk_item(char *buffer, btrfs_chunk_item * c);
void btrfs_io_print_chunk_item_stripe(char *buffer,
        btrfs_chunk_item_stripe * c);
void btrfs_io_print_dir_index(char *buffer, btrfs_dir_index * i);
void btrfs_io_print_extent_data(char *buffer, btrfs_extent_data * d);
void btrfs_io_print_extent_item(char *buffer, btrfs_extent_item * i);
void btrfs_io_print_header(char *buffer, btrfs_header * h);
void btrfs_io_print_item(char *buffer, btrfs_item * i);
void btrfs_io_print_item_type(char *buffer, uint8_t item_type);
void btrfs_io_print_inode_item(char *buffer, btrfs_inode_item * i);
void btrfs_io_print_key(char *buffer, btrfs_key * k);
void btrfs_io_print_root_item(char *buffer, btrfs_root_item * r);
// read methods
btrfs_block_ptr btrfs_io_read_block_ptr_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address);
btrfs_block_ptr btrfs_io_read_block_ptr_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address);
btrfs_dev_extent btrfs_io_read_dev_extent_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address);
btrfs_dev_extent btrfs_io_read_dev_extent_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address);
btrfs_dir_index btrfs_io_read_dir_index_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address, ssize_t size);
btrfs_dir_index btrfs_io_read_dir_index_pa(BTRFS_INFO * btrfs_info,
        uint64_t logical_address, ssize_t size);
btrfs_extent_data btrfs_io_read_extent_data_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address, uint32_t size);
btrfs_extent_data btrfs_io_read_extent_data_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address, uint32_t size);
btrfs_extent_item btrfs_io_read_extent_item_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address, uint32_t size);
btrfs_extent_item btrfs_io_read_extent_item_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address, uint32_t size);
btrfs_header btrfs_io_read_header_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address);
btrfs_header btrfs_io_read_header_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address);
btrfs_inode_item btrfs_io_read_inode_item_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address);
btrfs_inode_item btrfs_io_read_inode_item_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address);
btrfs_item btrfs_io_read_item_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address);
btrfs_item btrfs_io_read_item_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address);
btrfs_key btrfs_io_read_key_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address);
btrfs_key btrfs_io_read_key_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address);
btrfs_root_item btrfs_io_read_root_item_la(BTRFS_INFO * btrfs_info,
        uint64_t logical_address);
btrfs_root_item btrfs_io_read_root_item_pa(BTRFS_INFO * btrfs_info,
        uint64_t physical_address);
btrfs_superblock *btrfs_io_read_superblock_pa(TSK_FS_INFO * fs,
        uint64_t physical_address);

#endif                          /* TSK_BTRFS_H_ */
