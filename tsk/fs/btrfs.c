/*
 ** btrfs.c
 ** The  Sleuth Kit
 **
 ** Main source file of the Btrfs implementation for TSK
 **
 ** Andreas Juch [andreas.juch@gmail.com]
 ** Copyright (c) 2013-1014 Andreas Juch
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file btrfs.c
 * Btrfs filesystem functions.
 */

#include "tsk_fs_i.h"
#include "tsk_btrfs.h"
#include "queue.h"

/**
 * Print details about the file system to a file handle.
 *
 * @param fs File system to print details on
 * @param hFile File handle to print text to
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
btrfs_tsk_fsstat(TSK_FS_INFO * fs, FILE * hFile) {
    BTRFS_INFO *btrfs_info = (BTRFS_INFO *) fs;
    btrfs_superblock *sb = btrfs_info->superblock;

    // clean up any error messages that are lying around
    tsk_error_reset();

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "File System Type: Btrfs\n");

    char buf[32] = "";
    btrfs_io_print_uint64_t(buf, sb->total_bytes);
    tsk_fprintf(hFile, "Total Bytes: %s\n", buf);
    btrfs_io_print_uint64_t(buf, sb->bytes_used);
    tsk_fprintf(hFile, "Bytes Used: %s\n", buf);
    btrfs_io_print_uint64_t(buf, sb->log_addr_chunk_tree_root);
    tsk_fprintf(hFile, "Logical address of chunk tree root: %s\n", buf);
    btrfs_io_print_uint64_t(buf, sb->log_addr_root_tree_root);
    tsk_fprintf(hFile, "Logical address of root tree root: %s\n", buf);
    btrfs_io_print_uint64_t(buf, sb->nodesize);
    tsk_fprintf(hFile, "nodesize: %s\n", buf);
    btrfs_io_print_uint64_t(buf, sb->sectorsize);
    tsk_fprintf(hFile, "sectorsize: %s\n", buf);
    btrfs_io_print_uint64_t(buf, btrfs_info->nr_subvolumes);
    tsk_fprintf(hFile, "number of subvolumes: %s\n", buf);
    int i;
    for (i = 0; i < btrfs_info->nr_subvolumes; i++) {
        sprintf(buf, "%" PRIu64, btrfs_info->subvolume_ids[i]);
        tsk_fprintf(hFile, "subvolume id: %s\n", buf);
    }
    sprintf(buf, "%" PRIu64, fs->inum_count);
    tsk_fprintf(hFile, "number of inodes: %s\n", buf);

    tsk_fprintf(hFile, "Chunk Tree:\n");
    btrfs_chunk_print_entries(btrfs_info);

    return 0;
}

/* btrfs_close - close a btrfs file system */

static void
btrfs_tsk_close(TSK_FS_INFO * fs) {
    BTRFS_INFO *btrfs_info = (BTRFS_INFO *) fs;

    fs->tag = 0;
    free(btrfs_info->superblock);

    // delete the linked list of superblock_bootstrap
    struct chunk_entry_s *e = NULL;
    struct chunk_entry_s *tmp = NULL;

    TAILQ_FOREACH_SAFE(e, &(btrfs_info->chunks_head), pointers, tmp) {
        TAILQ_REMOVE(&(btrfs_info->chunks_head), e, pointers);
        free(e->chunk_item_stripes);
        free(e);
    }

    // delete the subvolume fs tree lists
    int i;
    for (i = 0; i < btrfs_info->nr_subvolumes; i++) {
        struct btrfs_tree_list_result_head *h =
                &(btrfs_info->subvolume_fs_tree_lists[i]);
        btrfs_tree_list_result_free(h);
    }
    free(btrfs_info->subvolume_fs_tree_lists);

    // delete the trees
    free(btrfs_info->subvolume_fsroots);

    // delete the ids
    free(btrfs_info->subvolume_ids);

    // free the dev_tree
    struct dev_extent_entry_s *e2 = NULL;
    struct dev_extent_entry_s *tmp2 = NULL;

    TAILQ_FOREACH_SAFE(e2, &(btrfs_info->dev_extents_head), pointers, tmp2) {
        TAILQ_REMOVE(&(btrfs_info->dev_extents_head), e2, pointers);
        free(e2);
    }

    // delete the inode mapping
    free(btrfs_info->inode_mapping);

    tsk_deinit_lock(&btrfs_info->lock);

    tsk_fs_free(fs);
}

/**
 * Resolves a logical address to a physical address.
 * @param fs
 * @param logical_addreass The logical address to resolve.
 * @return the physical address. -1 on error
 */
uint64_t
btrfs_resolve_logical_address(BTRFS_INFO * btrfs_info,
        uint64_t logical_address) {
    const uint64_t our_dev_id = btrfs_info->superblock->dev_item.dev_id;

    struct chunk_entry_s *e;

    TAILQ_FOREACH(e, &(btrfs_info->chunks_head), pointers) {
        btrfs_key k = e->key;
        uint64_t key_offset = k.offset;
        uint64_t size_of_chunk = e->chunk_item.size_of_chunk;
        if ((key_offset <= logical_address)
                && (logical_address < (key_offset + size_of_chunk))) {
            // found the address, return the address for this device
            int i;
            for (i = 0; i < e->chunk_item.num_stripes; i++) {
                btrfs_chunk_item_stripe *s =
                        (btrfs_chunk_item_stripe
                        *) (&e->chunk_item_stripes[i]);
                if (s->device_id == our_dev_id) {
                    uint64_t stripe_offset = s->offset;
                    return stripe_offset + (logical_address - key_offset);
                }
            }
            return -1;
        }
    }
    return -1;
}

/**
 * Resolves a physical address to a logical address.
 * @param fs
 * @param physical_address
 * @return The logical address, -1 on error.
 */
uint64_t
btrfs_resolve_physical_address(BTRFS_INFO * btrfs_info,
        uint64_t physical_address) {
    struct dev_extent_entry_s *e;

    TAILQ_FOREACH(e, &(btrfs_info->dev_extents_head), pointers) {
        uint64_t key_offset = e->key.offset;
        uint64_t extent_size = e->dev_extent.size;
        if (physical_address >= key_offset
                && physical_address <= (key_offset + extent_size)) {
            // found the right extent
            uint64_t result = e->dev_extent.logical_address
                    + (physical_address - key_offset);
            return result;
        }
    }
    return -1;
}

/**
 * Read the bootstrap information in the Btrfs superblock. This information is
 * necessary to get the logical address of the chunk tree (bootstrapping).
 * @param super The Btrfs superblock.
 * @return a linked list of superblock_bootstrap objects.
 */
void
btrfs_chunk_read_superblock_bootstrap_data(BTRFS_INFO * btrfs_info,
        btrfs_superblock * super) {
    // Initialize the TAILQ
    TAILQ_INIT(&(btrfs_info->chunks_head));

    int total_bytes = super->n;
    char n_bytes_valid[2048];
    memcpy(n_bytes_valid, super->bootstrap_chunks, 2048);
    int read = 0;

    while (read < total_bytes) {
        btrfs_key k;
        btrfs_io_parse_key(n_bytes_valid + read, &k);
        read += STRUCT_KEY_SIZE;
        read += btrfs_chunk_add(btrfs_info, k, n_bytes_valid + read);
    }
}

/**
 * Adds chunk data to the chunk list.
 * @param fs
 * @param k The key of the chunk.
 * @param data The data of the chunk consisting of chunk item and stripes.
 */
ssize_t
btrfs_chunk_add(BTRFS_INFO * btrfs_info, btrfs_key k, char *data) {
    btrfs_chunk_item ci;
    btrfs_io_parse_chunk_item(data, &ci);

    const int nr_stripes = ci.num_stripes;

    btrfs_chunk_item_stripe *stripes =
            tsk_malloc(sizeof (btrfs_chunk_item_stripe) * nr_stripes);
    int i;
    for (i = 0; i < nr_stripes; i++) {
        btrfs_chunk_item_stripe cis;
        btrfs_io_parse_chunk_item_stripe(data + STRUCT_CHUNK_ITEM_SIZE
                + (i * STRUCT_CHUNK_ITEM_STRIPE_SIZE), &cis);
        memcpy(&stripes[i], &cis, sizeof (btrfs_chunk_item_stripe));
    }

    struct chunk_entry_s *ce = tsk_malloc(sizeof (struct chunk_entry_s));
    memcpy(&ce->chunk_item, &ci, sizeof (btrfs_chunk_item));
    ce->chunk_item_stripes = stripes;
    memcpy(&ce->key, &k, sizeof (btrfs_key));

    TAILQ_INSERT_TAIL(&(btrfs_info->chunks_head), ce, pointers);

    return STRUCT_CHUNK_ITEM_SIZE +
            (nr_stripes * STRUCT_CHUNK_ITEM_STRIPE_SIZE);
}

/**
 * Prints all the known Chunks.
 * @param sb
 */
void
btrfs_chunk_print_entries(BTRFS_INFO * btrfs_info) {
    char buf[1024];

    printf("*** chunk entries ***\n");
    struct chunk_entry_s *iter;

    TAILQ_FOREACH(iter, &(btrfs_info->chunks_head), pointers) {
        btrfs_io_print_key(buf, (&iter->key));
        printf("%s", buf);
        printf("\n");
        btrfs_io_print_chunk_item(buf, (&iter->chunk_item));
        printf("%s", buf);
        printf("\n");
        int i;
        for (i = 0; i < iter->chunk_item.num_stripes; i++) {
            btrfs_chunk_item_stripe *s =
                    (btrfs_chunk_item_stripe *) (&iter->chunk_item_stripes[i]);
            btrfs_io_print_chunk_item_stripe(buf, s);
            printf("%s", buf);
            printf("\n");
        }
    }
    printf("*** end chunk entries ***\n");
}

static uint8_t
btrfs_tsk_istat(TSK_FS_INFO * fs, FILE * hFile, TSK_INUM_T inum,
        TSK_DADDR_T numblock, int32_t sec_skew) {
    BTRFS_INFO *btrfs_info = (BTRFS_INFO *) fs;

    btrfs_inode_mapping *m = btrfs_inode_resolve(btrfs_info, inum);
    btrfs_tree fstree =
            btrfs_subvolume_get_by_id(btrfs_info, m->subvolume_id);
    btrfs_inode_item_result res =
            btrfs_find_inode_item(btrfs_info, &fstree,
            m->inode_nr);

    if (res.found) {
        TSK_FS_FILE *f = tsk_malloc(sizeof (TSK_FS_FILE));
        f->fs_info = fs;
        f->meta = tsk_fs_meta_alloc(0);
        btrfs_read_metadata(btrfs_info, &(res.inode_item), NULL, inum,
                f->meta);
        tsk_fprintf(hFile, "Inode number %" PRIuINUM " (virtual)\n", inum);
        tsk_fprintf(hFile,
                "Btrfs inode number is %" PRIu64 " on subvolume %" PRIu64
                "\n", m->inode_nr, m->subvolume_id);
        tsk_fprintf(hFile, "=== stat info ===\n");
        tsk_fprintf(hFile, "Size:\t\t\t %" PRIu64 "\n", f->meta->size);
        tsk_fprintf(hFile, "Access time:\t\t %" PRIu64 "\n",
                f->meta->atime);
        tsk_fprintf(hFile, "Modified time:\t\t %" PRIu64 "\n",
                f->meta->mtime);
        tsk_fprintf(hFile, "Create time:\t\t %" PRIu64 "\n",
                f->meta->ctime);
        return 0;
    } else {
        return 1;
    }
}

btrfs_inode_item_result
btrfs_find_inode_item(BTRFS_INFO * info,
        btrfs_tree * fstree, uint64_t inode_number) {
    btrfs_inode_item_result res;
    btrfs_key k = btrfs_create_key(inode_number, ITEM_TYPE_INODE_ITEM, 0);

    btrfs_tree_search_result tsr = btrfs_tree_search(info, &k, fstree, 0,
            &btrfs_cmp_func_exact);

    if (tsr.found) {
        btrfs_io_parse_inode_item(tsr.data, &(res.inode_item));
        free(tsr.data);
        res.found = 1;
    } else {
        res.found = 0;
    }
    return res;
}

btrfs_dir_index_result
btrfs_find_dir_index(BTRFS_INFO * info,
        btrfs_tree * fstree, uint64_t inode_number, uint64_t dir_index) {
    btrfs_dir_index_result res;
    btrfs_key k = btrfs_create_key(inode_number, ITEM_TYPE_DIR_INDEX,
            dir_index);

    btrfs_tree_search_result tsr = btrfs_tree_search(info, &k, fstree, 0,
            &btrfs_cmp_func_exact);

    if (tsr.found) {
        btrfs_io_parse_dir_index(tsr.data, &(res.dir_index));
        free(tsr.data);
        res.found = 1;
    } else {
        res.found = 0;
    }
    return res;
}

/**
 * Inode iterator.
 * @param fs
 * @param start_inum
 * @param end_inum
 * @param flags
 * @param a_action
 * @param a_ptr
 * @return 0 on success, 1 on error.
 */
uint8_t
btrfs_tsk_inode_walk(TSK_FS_INFO * fs, TSK_INUM_T start_inum,
        TSK_INUM_T end_inum, TSK_FS_META_FLAG_ENUM flags,
        TSK_FS_META_WALK_CB a_action, void *a_ptr) {
    TSK_FS_FILE *file;

    // Allocate TSK_FS_FILE and META
    if ((file = tsk_fs_file_alloc(fs)) == NULL) {
        return 1;
    }
    if ((file->meta = tsk_fs_meta_alloc(BTRFS_FILE_CONTENT_LEN)) == NULL) {
        return 1;
    }

    int i;
    for (i = start_inum; i <= end_inum; i++) {
        if (btrfs_tsk_inode_lookup(fs, file, i)) {
            // ERROR
            return 1;
        } else {
            TSK_WALK_RET_ENUM retval = a_action(file, a_ptr);
            if (retval == TSK_WALK_STOP || retval == TSK_WALK_ERROR) {
                return 0;
            }
        }
    }
    return 0;
}

uint8_t
btrfs_tsk_block_walk(TSK_FS_INFO * a_fs, TSK_DADDR_T a_start_blk,
        TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
        TSK_FS_BLOCK_WALK_CB a_action, void *a_ptr) {
    char *myname = "btrfs_block_walk";
    BTRFS_INFO *btrfs_info = (BTRFS_INFO *) a_fs;
    TSK_FS_BLOCK *fs_block;
    TSK_DADDR_T addr;

    /*
     * Sanity checks.
     */
    if (a_start_blk < a_fs->first_block || a_start_blk > a_fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: start block: %" PRIuDADDR, myname,
                a_start_blk);
        return 1;
    }
    if (a_end_blk < a_fs->first_block || a_end_blk > a_fs->last_block
            || a_end_blk < a_start_blk) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: end block: %" PRIuDADDR, myname,
                a_end_blk);
        return 1;
    }

    // Allocate Block Struct
    if ((fs_block = tsk_fs_block_alloc(a_fs)) == NULL) {
        return 1;
    }

    // Iterate over the blocks.
    uint8_t callback;
    for (addr = a_start_blk; addr <= a_end_blk; addr++) {
        //printf("iterate over %llu \n" PRIuDADDR, addr);
        callback = 0;

        TSK_FS_BLOCK_FLAG_ENUM flags =
                btrfs_tsk_block_getflags(&(btrfs_info->fs_info), addr);

        // check if the callback should be called
        if ((flags & TSK_FS_BLOCK_FLAG_META)
                && (a_flags & TSK_FS_BLOCK_WALK_FLAG_META)) {
            callback = 1;
        } else if ((flags & TSK_FS_BLOCK_FLAG_CONT)
                && (a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT)) {
            callback = 1;
        } else if ((flags & TSK_FS_BLOCK_FLAG_ALLOC)
                && (a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)) {
            callback = 1;
        } else if ((flags & TSK_FS_BLOCK_FLAG_UNALLOC)
                && (a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC)) {
            callback = 1;
        }

        if (a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY) {
            flags |= TSK_FS_BLOCK_FLAG_AONLY;
        }

        if (tsk_fs_block_get_flag(a_fs, fs_block, addr, flags) == NULL) {
            tsk_error_set_errstr2("btrfs_block_walk: block %" PRIuDADDR,
                    addr);
            tsk_fs_block_free(fs_block);
            return 1;
        }

        if (callback == 1) {
            //printf("calling callback!\n");
            int retval = a_action(fs_block, a_ptr);
            if (retval == TSK_WALK_STOP) {
                break;
            } else if (retval == TSK_WALK_ERROR) {
                tsk_fs_block_free(fs_block);
                return 1;
            }
        }

    }
    return 0;
}

/**
 * \internal
 * Open part of a disk image as a Btrfs file system.
 *
 * @param img_info Disk image to analyze
 * @param offset Byte offset where file system starts
 * @param ftype Specific type of file system
 * @param test NOT USED
 * @returns NULL on error or if data is not a Btrfs file system
 */
TSK_FS_INFO *
btrfs_tsk_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
        TSK_FS_TYPE_ENUM ftype, uint8_t test) {

    BTRFS_INFO *btrfs_info;
    TSK_FS_INFO *fs;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (TSK_FS_TYPE_ISBTRFS(ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS Type in btrfs_open");
        return NULL;
    }

    if ((btrfs_info =
            (BTRFS_INFO *) tsk_malloc(sizeof (*btrfs_info))) == NULL) {
        return NULL;
    }

    fs = &(btrfs_info->fs_info);

    fs->ftype = ftype;
    fs->flags = 0;
    fs->img_info = img_info;
    fs->offset = offset;
    fs->tag = TSK_FS_INFO_TAG;
    fs->endian = TSK_LIT_ENDIAN;

    /*
     * Read the superblock struct.
     */
    btrfs_superblock *superblock = btrfs_io_read_superblock_pa(fs,
            BTRFS_SUPERBLOCK_LOCATION);
    btrfs_info->superblock = superblock;

    /*
     * Verify we are looking at an Btrfs image
     */
    if (strncmp(btrfs_info->superblock->magic, BTRFS_FS_MAGIC, 8) != 0) {
        fs->tag = 0;
        free(btrfs_info->superblock);
        free(btrfs_info);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("not an Btrfs file system (magic)");
        if (tsk_verbose)
            fprintf(stderr, "btrfs_open: invalid magic\n");
        return NULL;
    }

    /*
     * Set important attributes.
     */
    fs->block_size = 1024; // TODO determine if that is the right value.
    fs->first_block = 0;
    fs->last_block = fs->img_info->size / fs->block_size;
    fs->last_block_act = fs->last_block;

    /*
     * Parse the bootstrap data.
     */
    btrfs_chunk_read_superblock_bootstrap_data(btrfs_info,
            btrfs_info->superblock);

    /*
     * Read the chunk tree, address translation works after that step.
     */
    btrfs_info->chunk_tree = btrfs_tree_create_def_la(btrfs_info,
            btrfs_info->superblock->log_addr_chunk_tree_root);
    btrfs_chunk_read_tree(btrfs_info, &(btrfs_info->chunk_tree));

    /*
     * Set the root tree.
     */
    btrfs_info->root_tree = btrfs_tree_create_def_la(btrfs_info,
            btrfs_info->superblock->log_addr_root_tree_root);

    /*
     * Set the extent tree.
     */
    btrfs_info->extent_tree =
            btrfs_tree_get_tree_from_root_tree(btrfs_info,
            TREE_ID_EXTENT_TREE);

    /*
     * Set the dev tree.
     */
    btrfs_info->dev_tree = btrfs_tree_get_tree_from_root_tree(btrfs_info,
            TREE_ID_DEV_TREE);

    /*
     * Read the dev tree for translating physical -> logical addresses.
     */
    btrfs_read_dev_tree(btrfs_info);

    /*
     * Find and set all the subvolumes.
     */
    btrfs_subvolume_init(btrfs_info);

    /*
     * Count the number of inodes.
     */
    fs->inum_count = btrfs_inode_count(btrfs_info);
    fs->last_inum = fs->inum_count - 1;

    /*
     * Create a mapping for inodes.
     */
    btrfs_inode_create_mapping(btrfs_info);

    // set the top level subvolume fs tree
    btrfs_info->top_level_subvolume_fs_tree =
            btrfs_subvolume_get_by_id(btrfs_info, BTRFS_FIRST_SUBVOLUME_ID);

    /* Set the generic function pointers */
    fs->fsstat = btrfs_tsk_fsstat;
    fs->close = btrfs_tsk_close;
    fs->inode_walk = btrfs_tsk_inode_walk;
    fs->istat = btrfs_tsk_istat;
    fs->block_walk = btrfs_tsk_block_walk;
    fs->file_add_meta = btrfs_tsk_inode_lookup;
    fs->dir_open_meta = btrfs_tsk_dir_open_meta;
    fs->load_attrs = btrfs_tsk_load_attrs;
    fs->get_default_attr_type = btrfs_tsk_get_default_attr_type;
    fs->block_getflags = btrfs_tsk_block_getflags;

    return (fs);
}

/**
 * Compares two btrfs_keys.
 * @param k1
 * @param k2
 * @return 1 if k1 > k2; -1 if k1 < k2; 0 if k1 == k2;
 */
int
btrfs_compare_keys(btrfs_key * k1, btrfs_key * k2) {
    if (k1->object_id > k2->object_id) {
        return 1;
    } else if (k1->object_id < k2->object_id) {
        return -1;
    }

    if (k1->item_type > k2->item_type) {
        return 1;
    } else if (k1->item_type < k2->item_type) {
        return -1;
    }

    if (k1->offset > k2->offset) {
        return 1;
    } else if (k1->offset < k2->offset) {
        return -1;
    }

    // they are equal
    return 0;
}

/**
 * Reads the chunk tree from disk.
 * @param fs
 * @param ct
 */
void
btrfs_chunk_read_tree(BTRFS_INFO * btrfs_info, btrfs_tree * ct) {
    struct btrfs_tree_list_result_head list;
    TAILQ_INIT(&list);

    btrfs_tree_list(btrfs_info, ct, &list);

    struct btrfs_tree_list_result_s *iter;

    TAILQ_FOREACH(iter, &list, pointers) {
        if (iter->key.item_type == ITEM_TYPE_CHUNK_ITEM) {
            char *d = tsk_malloc(iter->data_size);
            tsk_fs_read(&(btrfs_info->fs_info), iter->physical_address, d,
                    iter->data_size);
            btrfs_chunk_add(btrfs_info, iter->key, d);
            free(d);
        }
    }

    btrfs_tree_list_result_free(&list);
}

/**
 * A compare function for btrfs_tree_search_advanced which searches for an
 * exact match of the supplied key.
 * @param fs
 * @param key
 * @param header
 * @param item_size
 * @param verbose
 * @return The index of the match or -1 if no match.
 */
int
btrfs_cmp_func_exact(btrfs_key * k1, btrfs_key * k2) {
    if (k1->object_id > k2->object_id) {
        return 1;
    } else if (k1->object_id < k2->object_id) {
        return -1;
    }

    if (k1->item_type > k2->item_type) {
        return 1;
    } else if (k1->item_type < k2->item_type) {
        return -1;
    }

    if (k1->offset > k2->offset) {
        return 1;
    } else if (k1->offset < k2->offset) {
        return -1;
    }

    // they are equal
    return 0;
}

/**
 * A compare function for btrfs_tree_search_advanced which searches for ranges.
 * The offset field of the keys in the tree is used as range which is added to
 * the object id. Example: Key(14,x,?) will match the tree Key(10,x,5).
 * @param fs
 * @param key The Key that is searched for. The offset is ignored.
 * @param header
 * @param item_size
 * @param verbose
 * @return The index of the match or -1 if no match.
 */
int
btrfs_cmp_func_extent_tree(btrfs_key * k1, btrfs_key * k2) {
    if (k1->item_type == k2->item_type &&
            k1->object_id <= k2->object_id <= (k1->object_id + k1->offset)) {
        return 0;
    } else {
        return -1;
    }
}

int
btrfs_cmp_func_match_all(btrfs_key * k1, btrfs_key * k2) {
    return 0;
}

/**
 * A compare function which searches for exact matches but ignores the offset field.
 * @param fs
 * @param key
 * @param header
 * @param item_size
 * @param verbose
 * @return
 */
int
btrfs_cmp_func_exact_ignore_offset(btrfs_key * k1, btrfs_key * k2) {
    if (k1->object_id > k2->object_id) {
        return 1;
    } else if (k1->object_id < k2->object_id) {
        return -1;
    }

    if (k1->item_type > k2->item_type) {
        return 1;
    } else if (k1->item_type < k2->item_type) {
        return -1;
    }

    // they are equal
    return 0;
}

/**
 * Search for a single entry in the tree. The first match is returned.
 * @param fs
 * @param key The key to search.
 * @param tree The tree to search in.
 * @param verbose Should verbose messages be printed (for debugging).
 * @param cmp The compare function which determines whether the found key
 * matches the search key.
 * @return
 */
btrfs_tree_search_result
btrfs_tree_search(BTRFS_INFO * btrfs_info,
        btrfs_key * key, btrfs_tree * tree, int verbose, compare_func cmp) {
    btrfs_tree_search_result r;
    r.found = 0;
    TSK_FS_INFO *fs = &(btrfs_info->fs_info);
    uint64_t physical_end_of_header = tree->physical_address
            + STRUCT_HEADER_SIZE;

    btrfs_header *h = &tree->header;

    char buf[1024] = "";
    btrfs_io_print_header(buf, h);
    //printf("header: %s\n", buf);

    if (h->level == 0) {
        // leaf node
        if (verbose) {
            printf("tw - leaf level 0\n");
        }
        int i;
        for (i = 0; i < h->number_items; i++) {
            if (verbose) {
                printf("- tw l %" PRIu8 " %d of %" PRIu32 " -", h->level,
                        i, h->number_items);
            }
            btrfs_key current_key = btrfs_io_read_key_pa(btrfs_info,
                    physical_end_of_header + (i * STRUCT_ITEM_SIZE));
            if (verbose) {
                btrfs_io_print_key(buf, &current_key);
                printf("current key: %s", buf);
                btrfs_io_print_key(buf, key);
                printf("comparing it to %s", buf);
            }
            int ret = cmp(&current_key, key);
            if (ret == 0) {
                btrfs_item it = btrfs_io_read_item_pa(btrfs_info,
                        physical_end_of_header + (i * STRUCT_ITEM_SIZE));
                memcpy((&r.key), (&it.key), sizeof (btrfs_key));
                char *d = tsk_malloc(it.data_size);
                tsk_fs_read(fs, physical_end_of_header + it.data_offset, d,
                        it.data_size);
                r.data = d;
                r.data_size = it.data_size;
                r.physical_address =
                        physical_end_of_header + it.data_offset;
                r.found = 1;
                return r;
            }
        }
    } else {
        // inner node
        if (verbose) {
            printf("tw - level %d \n", h->level);
        }
        int i;
        for (i = 0; i < h->number_items; i++) {
            if (verbose) {
                printf("- tw l %" PRIu8 " %d of %" PRIu32 " -", h->level,
                        i, h->number_items);
            }
            btrfs_key current_key = btrfs_io_read_key_pa(btrfs_info,
                    physical_end_of_header + (i * STRUCT_BLOCK_PTR_SIZE));
            if (verbose) {
                btrfs_io_print_key(buf, &current_key);
                printf("current key: %s", buf);
                btrfs_io_print_key(buf, key);
                printf("comparing it to %s", buf);
            }
            int ret = cmp(&current_key, key);
            if (ret == 0) {
                // the current key matches the search key, so this is the right branch.
                btrfs_block_ptr p = btrfs_io_read_block_ptr_pa(btrfs_info,
                        physical_end_of_header + (i * STRUCT_BLOCK_PTR_SIZE));
                btrfs_tree t = btrfs_tree_create_def_la(btrfs_info,
                        p.block_number);
                if (verbose) {
                    printf("tw recurse ret==0\n");
                }
                return btrfs_tree_search(btrfs_info, key, &t, verbose,
                        cmp);
            } else if (ret > 0 && i > 0) {
                // we have encountered a key that is larger than the one we search,
                // so the branch is the one before this!
                btrfs_block_ptr p = btrfs_io_read_block_ptr_pa(btrfs_info,
                        physical_end_of_header
                        + ((i - 1) * STRUCT_BLOCK_PTR_SIZE));
                btrfs_tree t = btrfs_tree_create_def_la(btrfs_info,
                        p.block_number);
                if (verbose) {
                    printf("tw recurse ret>0\n");
                }
                return btrfs_tree_search(btrfs_info, key, &t, verbose,
                        cmp);
            } else if (i == h->number_items - 1) {
                btrfs_block_ptr p = btrfs_io_read_block_ptr_pa(btrfs_info,
                        physical_end_of_header + (i * STRUCT_BLOCK_PTR_SIZE));
                btrfs_tree t = btrfs_tree_create_def_la(btrfs_info,
                        p.block_number);
                if (verbose) {
                    printf("tw recurse last\n");
                }
                return btrfs_tree_search(btrfs_info, key, &t, verbose,
                        cmp);
            }
        }
    }
    return r;
}

/**
 * Walk through the items of a Btrfs tree.
 * @param fs
 * @param tree
 * @param key
 * @param cmp
 * @param verbose
 * @param res
 * @param res_ptr
 * @return The number of found items.
 */
int
btrfs_tree_walk(BTRFS_INFO * btrfs_info, btrfs_tree * tree,
        btrfs_key * key, compare_func cmp, int verbose, result_func res,
        void *res_ptr) {
    return 0;
}

int
btrfs_tree_result_func_single(btrfs_tree_search_result * res,
        void *result_ptr) {
    btrfs_tree_search_result *res2 =
            (btrfs_tree_search_result *) result_ptr;
    res2->data = res->data;
    res2->data_size = res->data_size;
    res2->found = res->found;
    res2->key = res->key;
    res2->physical_address = res->physical_address;
    return 0;
}

int
btrfs_tree_result_func_list(btrfs_tree_search_result * res,
        void *result_ptr) {
    struct btrfs_tree_list_result_head *list_head =
            (struct btrfs_tree_list_result_head *) result_ptr;

    struct btrfs_tree_list_result_s *res2 =
            tsk_malloc(sizeof (struct btrfs_tree_list_result_s));
    res2->physical_address = res->physical_address;
    res2->data_size = res->data_size;
    memcpy(&(res2->key), &(res->key), sizeof (btrfs_key));

    TAILQ_INSERT_TAIL(list_head, res2, pointers);

    free(res->data);
    return 1;
}

btrfs_tree
btrfs_tree_create_def_la(BTRFS_INFO * fs, uint64_t logical_address) {
    uint64_t tree_pa = btrfs_resolve_logical_address(fs, logical_address);
    if (tree_pa != -1) {
        return btrfs_tree_create_def_pa(fs, tree_pa);
    } else {
        printf("Error creating tree def!");
    }
}

btrfs_tree
btrfs_tree_create_def_pa(BTRFS_INFO * fs, uint64_t physical_address) {
    btrfs_tree tree;
    btrfs_header tree_header =
            btrfs_io_read_header_pa(fs, physical_address);
    memcpy((&tree.header), &tree_header, sizeof (btrfs_header));
    tree.physical_address = physical_address;
    return tree;
}

int
btrfs_read_metadata(BTRFS_INFO * btrfs_info, btrfs_inode_item * ii,
        btrfs_dir_index * di, uint64_t virtual_inode, TSK_FS_META * meta) {
    // copy data into result
    if (ii) {
        meta->addr = virtual_inode;
        meta->atime = ii->st_Atime.epoch_seconds;
        meta->atime_nano = ii->st_Atime.nanoseconds;
        meta->ctime = ii->st_Ctime.epoch_seconds;
        meta->ctime_nano = ii->st_Ctime.nanoseconds;
        meta->gid = ii->st_gid;
        meta->mtime = ii->st_Mtime.epoch_seconds;
        meta->mtime_nano = ii->st_Mtime.nanoseconds;
        meta->uid = ii->st_uid;
        meta->size = ii->st_size;
    }

    if (di) {
        meta->type = btrfs_get_fs_meta_type(di->type);
    }

    return 0;
}

TSK_FS_META_TYPE_ENUM
btrfs_get_fs_meta_type(uint8_t dir_index_type) {
    if (dir_index_type == 1) {
        return TSK_FS_META_TYPE_REG;
    } else if (dir_index_type == 2) {
        return TSK_FS_META_TYPE_DIR;
    } else if (dir_index_type == 3) {
        return TSK_FS_META_TYPE_CHR;
    } else if (dir_index_type == 4) {
        return TSK_FS_META_TYPE_BLK;
    } else if (dir_index_type == 5) {
        return TSK_FS_META_TYPE_FIFO;
    } else if (dir_index_type == 6) {
        return TSK_FS_META_TYPE_SOCK;
    } else if (dir_index_type == 7) {
        return TSK_FS_META_TYPE_LNK;
    } else {
        return TSK_FS_META_TYPE_UNDEF;
    }
}

TSK_FS_NAME_TYPE_ENUM
btrfs_get_fs_name_type(uint8_t dir_index_type) {
    if (dir_index_type == 1) {
        return TSK_FS_NAME_TYPE_REG;
    } else if (dir_index_type == 2) {
        return TSK_FS_NAME_TYPE_DIR;
    } else if (dir_index_type == 3) {
        return TSK_FS_NAME_TYPE_CHR;
    } else if (dir_index_type == 4) {
        return TSK_FS_NAME_TYPE_BLK;
    } else if (dir_index_type == 5) {
        return TSK_FS_NAME_TYPE_FIFO;
    } else if (dir_index_type == 6) {
        return TSK_FS_NAME_TYPE_SOCK;
    } else if (dir_index_type == 7) {
        return TSK_FS_NAME_TYPE_LNK;
    } else {
        return TSK_FS_NAME_TYPE_UNDEF;
    }
}

btrfs_inode_ref_result
btrfs_find_inode_ref(BTRFS_INFO * btrfs_info,
        btrfs_tree * fstree, uint64_t real_inode, uint64_t parent_dir_index) {
    btrfs_inode_ref_result res;
    btrfs_key k = btrfs_create_key(real_inode, ITEM_TYPE_INODE_REF,
            parent_dir_index);

    btrfs_tree_search_result tsr;
    compare_func cmp;
    if (parent_dir_index == -1) {
        // ignore the offset in the search
        cmp = &btrfs_cmp_func_exact_ignore_offset;
    } else {
        cmp = &btrfs_cmp_func_exact;
    }
    tsr = btrfs_tree_search(btrfs_info, &k, fstree, 0, cmp);

    if (tsr.found) {
        btrfs_io_parse_inode_ref(tsr.data, &(res.inode_ref));
        res.key = tsr.key;
        free(tsr.data);
        res.found = 1;
    } else {
        res.found = 0;
    }
    return res;
}

/**
 *
 * @param a_fs
 * @param a_fs_dir
 * @param a_addr The logical address of the dir_index.
 * @return
 */
TSK_RETVAL_ENUM
btrfs_tsk_dir_open_meta(TSK_FS_INFO * a_fs,
        TSK_FS_DIR ** a_fs_dir, TSK_INUM_T a_addr) {
    BTRFS_INFO *btrfs_info = (BTRFS_INFO *) a_fs;

    TSK_FS_DIR *fs_dir;

    // Some sanity checks
    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("btrfs_dir_open_meta: inode value: %"
                PRIuINUM "\n", a_addr);
        return TSK_ERR;
    } else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
                ("btrfs_dir_open_meta: NULL fs_attr argument given");
        return TSK_ERR;
    }

    // get the right fs tree and the real inode number.
    btrfs_inode_mapping *m = btrfs_inode_resolve(btrfs_info, a_addr);
    btrfs_tree fstree =
            btrfs_subvolume_get_by_id(btrfs_info, m->subvolume_id);

    // get the relevant structures for this inode
    btrfs_inode_ref_result ir_res =
            btrfs_find_inode_ref(btrfs_info, &fstree,
            m->inode_nr, -1);
    btrfs_inode_item_result ii_res =
            btrfs_find_inode_item(btrfs_info, &fstree,
            m->inode_nr);
    btrfs_dir_index_result di_res =
            btrfs_find_dir_index(btrfs_info, &fstree,
            m->inode_nr, ir_res.inode_ref.dir_index);

    // get all dir_index items...
    btrfs_key k = btrfs_create_key(m->inode_nr, ITEM_TYPE_DIR_INDEX, 0);
    struct btrfs_tree_list_result_head tlr;
    TAILQ_INIT(&tlr);
    int nr_entries = btrfs_tree_list_filter(btrfs_info, &fstree, &tlr,
            &btrfs_cmp_func_exact_ignore_offset, &k);

    fs_dir = *a_fs_dir;
    if (fs_dir) {
        tsk_fs_dir_reset(fs_dir);
    } else {
        if ((*a_fs_dir = fs_dir =
                tsk_fs_dir_alloc(a_fs, a_addr, nr_entries))
                == NULL) {
            return TSK_ERR;
        }
    }

    if ((fs_dir->fs_file =
            tsk_fs_file_open_meta(a_fs, NULL, a_addr)) == NULL) {
        tsk_error_reset();
        tsk_error_errstr2_concat("- btrfs_dir_open_meta");
        return TSK_COR;
    }

    // Read the metadata for this directory.
    btrfs_dir_index *dir_index = NULL;
    if (di_res.found) {
        dir_index = &(di_res.dir_index);
    }
    btrfs_read_metadata(btrfs_info, &(ii_res.inode_item), dir_index,
            a_addr, fs_dir->fs_file->meta);
    fs_dir->fs_file->meta->flags |= TSK_FS_META_FLAG_ALLOC;

    fs_dir->fs_file->meta->addr = a_addr;

    struct btrfs_tree_list_result_s *iter;
    TSK_FS_NAME *fs_name = NULL;

    TAILQ_FOREACH(iter, &tlr, pointers) {
        if ((fs_name = tsk_fs_name_alloc(BTRFS_MAX_FILE_NAME_LEN + 1, 0))
                == NULL) {
            return TSK_ERR;
        }
        // a dir_index is the same as a (single entry) dir_item
        btrfs_dir_index di = btrfs_io_read_dir_index_pa(btrfs_info,
                iter->physical_address, iter->data_size);
        btrfs_inode_mapping m2;
        m2.subvolume_id = m->subvolume_id;
        m2.inode_nr = di.location_of_child.object_id;
        uint64_t virtual_inode =
                btrfs_inode_resolve_reverse(btrfs_info, &m2);
        fs_name->meta_addr = virtual_inode;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        fs_name->type = btrfs_get_fs_name_type(di.type);
        char *to = fs_name->name;
        char *from = di.data;
        memcpy(to, from, di.n);
        //to[di.n+1] = '\0';
        fs_name->name_size = di.n;
        fs_name->par_addr = a_addr;
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            printf("tsk_fs_dir_add error\n");
            return TSK_ERR;
        }
        free(di.data);
        tsk_fs_name_free(fs_name);
        fs_name = NULL;
    }
    btrfs_tree_list_result_free(&tlr);

    return TSK_OK;
}

/**
 * Lists all the keys that appear in a tree.
 * @param fs
 * @param tree The tree to be listed.
 * @param result A linked list of all the keys found in the tree.
 * @return The number of found results.
 */
int
btrfs_tree_list(BTRFS_INFO * btrfs_info, btrfs_tree * tree,
        struct btrfs_tree_list_result_head *list_head) {
    btrfs_key k = btrfs_create_key(0, 0, 0);
    return btrfs_tree_list_filter(btrfs_info, tree, list_head,
            &btrfs_cmp_func_match_all, &k);
}

/**
 *
 * @param fs
 * @param tree
 * @param list_head
 * @param cmp
 * @param k
 * @return The number of found results.
 */
int
btrfs_tree_list_filter(BTRFS_INFO * btrfs_info, btrfs_tree * tree,
        struct btrfs_tree_list_result_head *list_head, compare_func cmp,
        btrfs_key * k) {
    int verbose = 0;
    TSK_FS_INFO *fs = &(btrfs_info->fs_info);
    uint64_t physical_end_of_header = tree->physical_address
            + STRUCT_HEADER_SIZE;
    btrfs_tree_search_result r;
    r.found = 0;
    int num_results = 0;

    btrfs_header *h = &tree->header;

    if (h->level == 0) {
        // leaf node
        if (verbose) {
            printf("tl - leaf level 0\n");
        }
        int i;
        for (i = 0; i < h->number_items; i++) {
            if (verbose) {
                printf("- tl l %" PRIu8 " %d of %" PRIu32 " -", h->level,
                        i, h->number_items);
            }
            btrfs_item it = btrfs_io_read_item_pa(btrfs_info,
                    physical_end_of_header + (i * STRUCT_ITEM_SIZE));
            memcpy((&r.key), (&it.key), sizeof (btrfs_key));
            char *d = tsk_malloc(it.data_size);
            tsk_fs_read(fs, physical_end_of_header + it.data_offset, d,
                    it.data_size);
            r.data = d;
            r.data_size = it.data_size;
            r.physical_address = physical_end_of_header + it.data_offset;
            r.found = 1;
            num_results++;
            if (cmp(k, &(r.key)) == 0) {
                btrfs_tree_result_func_list(&r, list_head);
            } else {
                free(d);
            }
        }
    } else {
        // inner node
        if (verbose) {
            printf("tl - level %d \n", h->level);
        }
        int i;
        for (i = 0; i < h->number_items; i++) {
            if (verbose) {
                printf("- tl l %" PRIu8 " %d of %" PRIu32 " -", h->level,
                        i, h->number_items);
            }
            btrfs_block_ptr p = btrfs_io_read_block_ptr_pa(btrfs_info,
                    physical_end_of_header + (i * STRUCT_BLOCK_PTR_SIZE));
            btrfs_tree t =
                    btrfs_tree_create_def_la(btrfs_info, p.block_number);
            if (verbose) {
                printf("tl recurse ret==0\n");
            }
            num_results +=
                    btrfs_tree_list_filter(btrfs_info, &t, list_head, cmp, k);
        }
    }
    return num_results;
}

/**
 * Prints a list of keys that were found in a tree list.
 * @param l
 */
void
btrfs_tree_list_print(struct btrfs_tree_list_result_head *l) {
    struct btrfs_tree_list_result_s *iter;
    char buf[1024] = "";
    printf("Tree List:\n");

    TAILQ_FOREACH(iter, l, pointers) {
        btrfs_io_print_key(buf, &(iter->key));
        printf(". %s\n", buf);
    }
    printf("End of Tree List.\n");
}

/**
 * Frees a list of keys.
 * @param l
 */
void
btrfs_tree_list_result_free(struct btrfs_tree_list_result_head *l) {
    struct btrfs_tree_list_result_s *iter = NULL;
    struct btrfs_tree_list_result_s *tmp = NULL;

    TAILQ_FOREACH_SAFE(iter, l, pointers, tmp) {
        TAILQ_REMOVE(l, iter, pointers);
        free(iter);
    }
}

int
btrfs_subvolume_is_id(uint64_t id) {
    if (id == BTRFS_FIRST_SUBVOLUME_ID
            || (id >= BTRFS_MIN_SUBVOLUME_ID && id < BTRFS_MAX_SUBVOLUME_ID)) {
        return TRUE;
    } else {
        return FALSE;
    }
}

/**
 * Finds all the subvolumes and initializes the information in the BTRFS_INFO.
 * @param fs
 */
void
btrfs_subvolume_init(BTRFS_INFO * btrfs_info) {

    // List the root tree.
    struct btrfs_tree_list_result_head rt_list;
    TAILQ_INIT(&rt_list);
    btrfs_tree_list(btrfs_info, &(btrfs_info->root_tree), &rt_list);

    // Find all the subvolumes in the list.
    struct btrfs_tree_list_result_s *iter;

    // Count the subvolumes.
    uint64_t subvol_count = 0;
    char buf[1024] = "";

    TAILQ_FOREACH(iter, &rt_list, pointers) {
        btrfs_key *k = &iter->key;
        btrfs_io_print_key(buf, k);
        if (k->item_type == ITEM_TYPE_ROOT_ITEM && k->offset == 0
                && btrfs_subvolume_is_id(k->object_id)) {
            // This key belongs to a subvolume.
            subvol_count = subvol_count + 1;
        }
    }
    btrfs_info->nr_subvolumes = subvol_count;

    // Initialize the arrays.
    btrfs_info->subvolume_ids =
            tsk_malloc(sizeof (uint64_t) * subvol_count);
    btrfs_info->subvolume_fsroots =
            tsk_malloc(sizeof (btrfs_tree) * subvol_count);
    btrfs_info->subvolume_fs_tree_lists =
            tsk_malloc(sizeof (struct btrfs_tree_list_result_head) *
            subvol_count);

    // Populate the arrays.
    int i = 0;

    TAILQ_FOREACH(iter, &rt_list, pointers) {
        btrfs_key *k = &iter->key;
        if (k->item_type == ITEM_TYPE_ROOT_ITEM && k->offset == 0
                && btrfs_subvolume_is_id(k->object_id)) {
            btrfs_info->subvolume_ids[i] = k->object_id;
            btrfs_root_item ri = btrfs_io_read_root_item_pa(btrfs_info,
                    iter->physical_address);
            btrfs_tree t = btrfs_tree_create_def_la(btrfs_info,
                    ri.block_number_root_node);
            memcpy(&(btrfs_info->subvolume_fsroots[i]), &t,
                    sizeof (btrfs_tree));
            struct btrfs_tree_list_result_head *tlr =
                    &(btrfs_info->subvolume_fs_tree_lists[i]);
            TAILQ_INIT(tlr);
            btrfs_tree_list(btrfs_info, &t, tlr);
            i++;
        }
    }
    btrfs_tree_list_result_free(&rt_list);
}

btrfs_tree
btrfs_subvolume_get_by_id(BTRFS_INFO * btrfs_info, uint64_t id) {
    int i;
    for (i = 0; i < btrfs_info->nr_subvolumes; i++) {
        if (btrfs_info->subvolume_ids[i] == id) {
            return btrfs_info->subvolume_fsroots[i];
        }
    }
    printf("Could not find subvolume with id %" PRIu64 "\n", id);
}

uint64_t
btrfs_inode_count(BTRFS_INFO * btrfs_info) {
    uint64_t result = 0;
    int i;
    for (i = 0; i < btrfs_info->nr_subvolumes; i++) {
        struct btrfs_tree_list_result_head *h =
                &(btrfs_info->subvolume_fs_tree_lists[i]);
        struct btrfs_tree_list_result_s *r;

        TAILQ_FOREACH(r, h, pointers) {
            if (r->key.item_type == ITEM_TYPE_INODE_ITEM) {
                result = result + 1;
            }
        }
    }
    return result;
}

void
btrfs_inode_create_mapping(BTRFS_INFO * btrfs_info) {
    TSK_FS_INFO *fs = &(btrfs_info->fs_info);
    if (fs->inum_count == 0) {
        printf("inode create mapping Error, no inodes!\n");
        return;
    }
    btrfs_info->inode_mapping =
            tsk_malloc(sizeof (btrfs_inode_mapping) * fs->inum_count);
    uint64_t current_inode = 0;
    int i;
    for (i = 0; i < btrfs_info->nr_subvolumes; i++) {
        struct btrfs_tree_list_result_head *h =
                &(btrfs_info->subvolume_fs_tree_lists[i]);
        struct btrfs_tree_list_result_s *r;

        TAILQ_FOREACH(r, h, pointers) {
            if (r->key.item_type == ITEM_TYPE_INODE_ITEM) {
                btrfs_inode_mapping m;

                m.inode_nr = r->key.object_id;
                m.subvolume_id = btrfs_info->subvolume_ids[i];
                memcpy(&(btrfs_info->inode_mapping[current_inode]), &m,
                        sizeof (btrfs_inode_mapping));
                current_inode = current_inode + 1;
            }
        }
    }
}

btrfs_inode_mapping *
btrfs_inode_resolve(BTRFS_INFO * btrfs_info, uint64_t virtual_inode_nr) {
    TSK_FS_INFO *fs = &(btrfs_info->fs_info);
    if (virtual_inode_nr <= fs->last_inum) {
        return &(btrfs_info->inode_mapping[virtual_inode_nr]);
    } else {
        printf("ERROR invalid inode id %" PRIu64 "\n", virtual_inode_nr);
        printf("min: 0 max: %" PRIuINUM "\n", fs->last_inum);
        return NULL;
    }
}

uint64_t
btrfs_inode_resolve_reverse(BTRFS_INFO * btrfs_info,
        btrfs_inode_mapping * map) {
    TSK_FS_INFO *fs = &(btrfs_info->fs_info);
    btrfs_inode_mapping *m;

    int i;
    for (i = 0; i < fs->inum_count; i++) {
        m = &(btrfs_info->inode_mapping[i]);
        if (m->inode_nr == map->inode_nr
                && m->subvolume_id == map->subvolume_id) {
            return i;
        }
    }
    return -1;
}

btrfs_tree
btrfs_tree_get_tree_from_root_tree(BTRFS_INFO * btrfs_info, int tree_id) {
    // The key to find.
    btrfs_key k = btrfs_create_key(tree_id, ITEM_TYPE_ROOT_ITEM, 0);

    btrfs_tree_search_result tsr = btrfs_tree_search(btrfs_info, &k,
            &(btrfs_info->root_tree), 0, &btrfs_cmp_func_exact);
    if (tsr.found) {
        btrfs_root_item ri;
        btrfs_io_parse_root_item(tsr.data, &ri);
        uint64_t block_nr = ri.block_number_root_node;
        free(tsr.data);
        return btrfs_tree_create_def_la(btrfs_info, block_nr);
    } else {
        printf("Could not find tree!\n");
    }
}

void
btrfs_read_dev_tree(BTRFS_INFO * btrfs_info) {
    struct btrfs_tree_list_result_head tlr;
    TAILQ_INIT(&tlr);
    btrfs_tree_list(btrfs_info, &(btrfs_info->dev_tree), &tlr);

    struct btrfs_tree_list_result_s *iter;

    struct dev_extent_entry_s *new_entry;

    // Initialize the TAILQ
    TAILQ_INIT(&(btrfs_info->dev_extents_head));

    TAILQ_FOREACH(iter, &tlr, pointers) {
        btrfs_dev_extent e = btrfs_io_read_dev_extent_pa(btrfs_info,
                iter->physical_address);

        // create the new entry
        new_entry = tsk_malloc(sizeof (struct dev_extent_entry_s));
        memcpy(&(new_entry->dev_extent), &e, sizeof (btrfs_dev_extent));
        memcpy(&(new_entry->key), &(iter->key), sizeof (btrfs_key));

        // insert it into the list
        TAILQ_INSERT_TAIL(&(btrfs_info->dev_extents_head), new_entry,
                pointers);
    }

    // free the result
    btrfs_tree_list_result_free(&tlr);
}

/**
 * Return information about a block.
 * @param a_fs The BTRFS_INFO
 * @param a_addr
 */
TSK_FS_BLOCK_FLAG_ENUM
btrfs_tsk_block_getflags(TSK_FS_INFO * fs_info, TSK_DADDR_T a_addr) {
    BTRFS_INFO *btrfs_info = (BTRFS_INFO *) fs_info;
    uint64_t phys_addr = a_addr * btrfs_info->fs_info.block_size;
    uint64_t log_addr =
            btrfs_resolve_logical_address(btrfs_info, phys_addr);

    char buf[1024] = "";

    if (log_addr == -1) {
        return TSK_FS_BLOCK_FLAG_UNALLOC;
    } else {
        struct btrfs_tree_list_result_head tlr;
        TAILQ_INIT(&tlr);
        btrfs_tree_list(btrfs_info, &(btrfs_info->extent_tree), &tlr);
        struct btrfs_tree_list_result_s *iter;

        int found = FALSE;
        btrfs_extent_item ei = {};

        TAILQ_FOREACH(iter, &tlr, pointers) {
            if (iter->key.item_type == ITEM_TYPE_EXTENT_ITEM
                    && (iter->key.object_id <= log_addr
                    && log_addr <=
                    (iter->key.object_id + iter->key.offset))) {
                found = TRUE;
                btrfs_extent_item ei2 =
                        btrfs_io_read_extent_item_pa(btrfs_info,
                        iter->physical_address, iter->data_size);
                memcpy(&ei, &ei2, iter->data_size);
                break;
            }
        }

        btrfs_tree_list_result_free(&tlr);

        if (found) {
            btrfs_extent_item ei;

            if (ei.flags == EXTENT_ITEM_TREE_BLOCK) {
                return TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_META;
            } else if (ei.flags == EXTENT_ITEM_DATA) {
                return TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_CONT;
            } else {
                if (tsk_verbose) {
                    btrfs_io_print_extent_item(buf, &ei);
                    printf("%s\n", buf);
                    printf("unknown code %" PRIu64 "\n", ei.flags);
                }
                return TSK_FS_BLOCK_FLAG_ALLOC;
            }
        } else {
            return TSK_FS_BLOCK_FLAG_UNALLOC;
        }
    }
}

/**
 *
 * @param fs
 * @param a_fs_file
 * @param inum The virtual inode number.
 * @return 1 on error, 0 on success.
 */
static uint8_t
btrfs_tsk_inode_lookup(TSK_FS_INFO * fs, TSK_FS_FILE * a_fs_file,
        TSK_INUM_T inum) {
    BTRFS_INFO *btrfs_info = (BTRFS_INFO *) fs;

    if (a_fs_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("btrfs_inode_lookup: fs_file is NULL");
        return 1;
    }

    if (a_fs_file->meta == NULL) {
        if ((a_fs_file->meta = tsk_fs_meta_alloc(0)) == NULL)
            return 1;
    } else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    // Resolve the virtual inode.
    btrfs_inode_mapping *mapping = btrfs_inode_resolve(btrfs_info, inum);

    // Get the right FS tree.
    btrfs_tree fstree = btrfs_subvolume_get_by_id(btrfs_info,
            mapping->subvolume_id);

    // Get the directory inode_item and inode_ref
    btrfs_inode_item_result iir =
            btrfs_find_inode_item(btrfs_info, &fstree,
            mapping->inode_nr);
    btrfs_inode_ref_result irr = btrfs_find_inode_ref(btrfs_info, &fstree,
            mapping->inode_nr, -1);
    btrfs_dir_index_result dir;
    dir.found = 0;
    if (irr.found) {
        dir = btrfs_find_dir_index(btrfs_info, &fstree, irr.key.offset,
                irr.inode_ref.dir_index);
    }

    btrfs_dir_index *dir_index = NULL;
    if (dir.found) {
        dir_index = &(dir.dir_index);
    }
    if (iir.found) {
        // Read the metadata from the inode item
        btrfs_read_metadata(btrfs_info, &(iir.inode_item), dir_index, inum,
                a_fs_file->meta);

        // Set the TSK_FS_FILE attributes.
        a_fs_file->fs_info = fs;
        a_fs_file->meta->flags = TSK_FS_META_FLAG_ALLOC;
        return 0;
    } else {
        printf("inode lookup fail\n");
        return 1;
    }
}

btrfs_key
btrfs_create_key(uint64_t object_id, uint8_t item_type, uint64_t offset) {
    btrfs_key k;
    k.object_id = object_id;
    k.item_type = item_type;
    k.offset = offset;
    return k;
}

uint8_t
btrfs_tsk_load_attrs(TSK_FS_FILE * fs_file) {
    TSK_FS_META *fs_meta = fs_file->meta;
    TSK_FS_INFO *fs = fs_file->fs_info;
    BTRFS_INFO *btrfs_info = (BTRFS_INFO *) fs;

    if (tsk_verbose) {
        tsk_fprintf(stderr, "TSK_FS_FILE size is %lu \n", fs_meta->size);
    }

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (tsk_verbose) {
        tsk_fprintf(stderr,
                "btrfs_tsk_load_attrs: Processing file %" PRIuINUM "\n",
                fs_meta->addr);
    }

    if ((fs_file == NULL) || (fs_file->meta == NULL)
            || (fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
                ("btrfs_tsk_load_attrs: called with NULL pointers");
        return 1;
    }

    // see if we have already loaded the runs
    if ((fs_meta->attr != NULL)
            && (fs_meta->attr_state == TSK_FS_META_ATTR_STUDIED)) {
        return 0;
    } else if (fs_meta->attr_state == TSK_FS_META_ATTR_ERROR) {
        return 1;
    }// not sure why this would ever happen, but...
    else if (fs_meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    } else if (fs_meta->attr == NULL) {
        fs_meta->attr = tsk_fs_attrlist_alloc();
    }

    TSK_FS_ATTR *fs_attr;

    btrfs_inode_mapping *mapping = btrfs_inode_resolve(btrfs_info,
            fs_file->meta->addr);
    if (tsk_verbose) {
        tsk_fprintf(stderr,
                "inode info: virtual: %lu real: %lu subvol: %lu",
                fs_file->meta->addr, mapping->inode_nr, mapping->subvolume_id);
    }

    // find the extent data in the fs tree
    btrfs_tree fstree = btrfs_subvolume_get_by_id(btrfs_info,
            mapping->subvolume_id);
    btrfs_key extent_data_key = btrfs_create_key(mapping->inode_nr,
            ITEM_TYPE_EXTENT_DATA, 0);

    // Find all extend data for the inode.
    struct btrfs_tree_list_result_head tlr;
    TAILQ_INIT(&tlr);
    btrfs_tree_list_filter(btrfs_info, &fstree, &tlr,
            &btrfs_cmp_func_exact_ignore_offset, &extent_data_key);

    uint64_t block_size = btrfs_info->fs_info.block_size;

    struct btrfs_tree_list_result_s *iter;

    TAILQ_FOREACH(iter, &tlr, pointers) {
        btrfs_extent_data ed = btrfs_io_read_extent_data_pa(btrfs_info,
                iter->physical_address, iter->data_size);
        if (tsk_verbose) {
            char buf[1024] = "";
            btrfs_io_print_extent_data(buf, &ed);

            tsk_fprintf(stderr, "found extent data: %s\n", buf);
            btrfs_io_print_key(buf, &iter->key);
            tsk_fprintf(stderr, "former extent data's key: %s\n", buf);
            tsk_fprintf(stderr,
                    "extent data physical addr: %" PRIu64 " size: %" PRIu64
                    "\n", iter->physical_address, iter->data_size);
        }

        if (ed.type == 0) {
            // Inline extent
            if (tsk_verbose) {
                tsk_fprintf(stderr, "Inline extent.\n");
            }

            if ((fs_attr =
                    tsk_fs_attrlist_getnew(fs_meta->attr, TSK_FS_ATTR_RES))
                    == NULL) {
                free(ed.inline_data);
                return 1;
            }

            if (tsk_fs_attr_set_str(fs_file, fs_attr, NULL,
                    TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
                    ed.inline_data, ed.size_of_decoded_extent)) {
                free(ed.inline_data);
                fprintf(stderr, "error tsk_fs_attr_set_str\n");
                return 1;
            }
            free(ed.inline_data);
        } else {
            // No inline extent.
            if (tsk_verbose) {
                tsk_fprintf(stderr, "Normal extent.\n");
            }
            uint64_t offset = iter->key.offset / block_size;
            if (offset == 0) {
                // start of the file, calculate skiplen
                if ((fs_attr =
                        tsk_fs_attrlist_getnew(fs_meta->attr,
                        TSK_FS_ATTR_NONRES))
                        == NULL) {
                    return 1;
                }

                fs_attr->nrd.skiplen =
                        btrfs_resolve_logical_address(btrfs_info,
                        ed.extent_logical_address) % block_size;
                if (tsk_verbose) {
                    tsk_fprintf(stderr, "skiplen is %" PRIu32 "\n",
                            fs_attr->nrd.skiplen);
                }

                TSK_FS_ATTR_RUN *data_run =
                        btrfs_convert_extent_data_to_data_run(btrfs_info, &ed,
                        offset);

                // initialize the data run
                if (tsk_fs_attr_set_run(fs_file, fs_attr, data_run, NULL,
                        TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
                        fs_meta->size, fs_meta->size, fs_meta->size, 0,
                        0)) {
                    return 1;
                }
            } else {
                // inside a file, add the offset
                if (tsk_verbose) {
                    tsk_fprintf(stderr,
                            "offset (blocks) inside file %" PRIu64 "\n",
                            offset);
                }

                TSK_FS_ATTR_RUN *data_run =
                        btrfs_convert_extent_data_to_data_run(btrfs_info, &ed,
                        offset);
                // save the run
                tsk_fs_attr_append_run(fs, fs_attr, data_run);
            }
        }
    }

    btrfs_tree_list_result_free(&tlr);

    fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;

    fprintf(stderr, "tsk load attrs finished\n");

    return 0;
}

TSK_FS_ATTR_RUN *
btrfs_convert_extent_data_to_data_run(BTRFS_INFO * btrfs_info,
        btrfs_extent_data * ed, uint64_t offset) {
    uint64_t block_size = btrfs_info->fs_info.block_size;
    uint64_t extent_phys_addr = btrfs_resolve_logical_address(btrfs_info,
            ed->extent_logical_address);
    if (tsk_verbose) {
        tsk_fprintf(stderr,
                "file contents la %" PRIu64 ", pa %" PRIu64 "\n",
                ed->extent_logical_address, extent_phys_addr);
    }
    if (extent_phys_addr == -1 && tsk_verbose) {
        fprintf(stderr, "extent phys addr is invalid\n");
    }
    uint64_t data_start_addr = extent_phys_addr + ed->extent_offset;
    uint64_t data_len = ed->extent_size;
    uint64_t data_len_blocks = data_len_blocks = data_len / block_size;
    if (tsk_verbose) {
        tsk_fprintf(stderr, "extent_phys_start_addr: %" PRIu64
                " extent_size: %" PRIu64 " offset: %" PRIu64 "\n",
                data_start_addr, data_len, offset);
    }
    if ((data_len % block_size) != 0) {
        data_len_blocks++;
    }
    uint64_t data_start_block = data_start_addr / block_size;
    if (data_start_block % block_size != 0 && tsk_verbose) {
        tsk_fprintf(stderr,
                "warn! data start block is wrong, mod is not zero!!!\n");
    }

    if (tsk_verbose) {
        tsk_fprintf(stderr,
                "data_start_block %" PRIu64 ", data_len_blocks %" PRIu64
                ", offset: %" PRIu64 ", bs %" PRIu64, data_start_block,
                data_len_blocks, offset, block_size);
    }

    TSK_FS_ATTR_RUN *data_run;

    // make a non-resident run
    data_run = tsk_fs_attr_run_alloc();
    data_run->addr = data_start_block;
    data_run->len = data_len_blocks;
    data_run->offset = offset;

    if (tsk_verbose) {
        fprintf(stderr,
                "btrfs_convert_extent_data_to_data_run finished \n");
    }
    return data_run;
}

TSK_FS_ATTR_TYPE_ENUM
btrfs_tsk_get_default_attr_type(const TSK_FS_FILE * a_file) {
    return TSK_FS_ATTR_TYPE_DEFAULT;
}

uint64_t
btrfs_get_pa_from_extent_data_ref(BTRFS_INFO * btrfs_info,
        btrfs_extent_data_ref * edr) {
    btrfs_tree fstree = btrfs_subvolume_get_by_id(btrfs_info,
            edr->root_objectid);
    btrfs_key k =
            btrfs_create_key(edr->object_id_owner, ITEM_TYPE_EXTENT_DATA,
            edr->offset);
    btrfs_tree_search_result tsr =
            btrfs_tree_search(btrfs_info, &k, &fstree, 1,
            &btrfs_cmp_func_exact);
    btrfs_extent_data ed;
    btrfs_io_parse_extent_data(tsr.data, &ed);
    char buf[1024] = "";
    btrfs_io_print_extent_data(buf, &ed);
    printf("found the extent data %s \n", buf);
    return 0;
}
