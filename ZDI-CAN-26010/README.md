The following is a copy of the advisory i submitted to the ZDI for CVE-2025-20234 / ZDI-25-417 / ZDI-CAN-26010.
More information can be found [here](https://www.zerodayinitiative.com/advisories/ZDI-25-417/)

1.	Vulnerability Title
  a.	e.g. Vendor Product Module Vulnerability Remote Code Execution Vulnerability

Cisco Clamav LibClamav Denial of Service/OOB read vulnerability

2.	High-level overview of the vulnerability and the possible effect of using it

The vulnerability can be used to read out of bounds or crash a clamscan instance, or where clamd and clamdscan are used, crash the clamd daemon.
This has the effect of killing the daemon and where there is no mechanism to automatically restart it, disabling clamav.

3.	Exact product that was found to be vulnerable including complete version information

Current version of clamav, tested POC on release 1.4.1 and independantly tested on commit d6d25c33d9cbed93f653da0bb22af9b349fded40 (most recent commit at time of writing).

4.	Root Cause Analysis (recommended but not required)
  a.	Detailed description of the vulnerability
  b.	Code flow from input to the vulnerable condition
  c.	Buffer size, injection point, etc.
  d.	Suggested fixes are also welcomed

The vulnerability arises during scanning of UDF files within libclamav, specifically inside `cli_scanudf` where `findFileEntries` is called:

```c
// Input is user controlled
static cl_error_t findFileEntries(const uint8_t *const input, PointerList *pfil)
{
    cl_error_t ret        = CL_SUCCESS;
    const uint8_t *buffer = input;
    uint16_t tagId        = getDescriptorTagId((DescriptorTag *)buffer);
    size_t bufUsed;
    size_t fedDescSize;

    while (FILE_ENTRY_DESCRIPTOR == tagId) {
        // [0] Writes the buffer ptr into the ptr list (into idxs)
        if (CL_SUCCESS != (ret = insertPointer(pfil, buffer))) {
            goto done;
        }

        /*This is how far into the Volume we already are.*/
        bufUsed     = buffer - input;
        fedDescSize = getFileEntryDescriptorSize((FileEntryDescriptor *)buffer);

        /* Check that it's safe to read the header for the next FileEntryDescriptor */
        if (VOLUME_DESCRIPTOR_SIZE < (fedDescSize + bufUsed + FILE_ENTRY_DESCRIPTOR_SIZE_KNOWN)) {
            break;
        }

        buffer = buffer + fedDescSize;
        tagId  = getDescriptorTagId((DescriptorTag *)buffer);
    }

done:
    return ret;
}

```

The bug is at [0], if we are the first entry we simply add us into the ptr list regardless of what our fedDescSize is, unchecked. After which we will exit the loop.

This means we get to call `parseFileEntryDescriptor` afterwards with an invalid `FileEntryDescriptor`:

```c
static bool parseFileEntryDescriptor(cli_ctx *ctx, FileEntryDescriptor *fed, PartitionDescriptor *pPartitionDescriptor, LogicalVolumeDescriptor *pLogicalVolumeDescriptor, FileIdentifierDescriptor *fileIdentifierDescriptor)
{
    bool ret                    = false;
    uint16_t tagId              = getDescriptorTagId(&fed->tag);
    void *allocation_descriptor = NULL;

    size_t file_entry_descriptor_size;
    size_t allocation_descriptor_len;

    if (FILE_ENTRY_DESCRIPTOR != tagId) {
        cli_warnmsg("parseFileEntryDescriptor: Tag ID of 0x%x does not match File Entry Descriptor.\n", tagId);
        goto done;
    }

    tagId = getDescriptorTagId(&fileIdentifierDescriptor->tag);
    if (FILE_IDENTIFIER_DESCRIPTOR != tagId) {
        cli_warnmsg("parseFileEntryDescriptor: Tag ID of 0x%x does not match File Identifier Descriptor.\n", tagId);
        goto done;
    }

    // Calculate pointer for the allocation descriptor.
    // The allocation descriptors are the last bytes of the Extended File Entry.
    // See Section 14.17 in https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf
    // [0] This takes from idxs[0], which could be buggy for us, dont know what the comment is on about.
    file_entry_descriptor_size = getFileEntryDescriptorSize(fed);
    allocation_descriptor_len  = le32_to_host(fed->allocationDescLen);

    // [1] Given we control both of these, as long as the calculation doesnt overflow in getFileEntryDescriptor and allocation_descriptor_len is
    // smaller than file_entry_descriptor_size we proceed.
    if (allocation_descriptor_len > file_entry_descriptor_size) {
        cli_dbgmsg("parseFileEntryDescriptor: Allocation Descriptor Length is greater than the File Entry Descriptor Size.\n");
        goto done;
    }
    // [2] With a big enough file_entry_descriptor_size this ptr will be invalid/OOB.
    allocation_descriptor = (void *)((uint8_t *)fed + (file_entry_descriptor_size - allocation_descriptor_len));

    // The Allocation Descriptor was taken from the end of the  File Entry Descriptor.
    // We already verified that the File Entry Descriptor is within the fmap,
    // so it's safe to say the Allocation Descriptor is also within the fmap.
    // No need to use an `fmap_need...()` function here.

    // Extract the file.
    // [3] We then use this ptr
    if (CL_SUCCESS != extractFile(ctx, pPartitionDescriptor, pLogicalVolumeDescriptor,
                                  allocation_descriptor,
                                  allocation_descriptor_len,
                                  le16_to_host(fed->icbTag.flags), fileIdentifierDescriptor)) {
        cli_dbgmsg("parseFileEntryDescriptor: Failed to extract file.\n");
        goto done;
    }

    ret = true;
done:
    return ret;
}
```

[0,1,2,3] this leads to a situation where the `allocation_descriptor` pointer can be out of bounds. This pointer is then passed into `extractFile` at [3].

```c
static cl_error_t extractFile(cli_ctx *ctx, PartitionDescriptor *pPartitionDescriptor, LogicalVolumeDescriptor *pLogicalVolumeDescriptor,
                              void *allocation_descriptor,
                              size_t allocation_descriptor_len,
                              uint16_t icbFlags, FileIdentifierDescriptor *fileIdentifierDescriptor)
{
    cl_error_t ret                     = CL_EPARSE;
    uint32_t offset                    = 0;
    uint32_t length                    = 0;
    uint8_t *contents                  = NULL;
    uint32_t partitionStartingLocation = le32_to_host(pPartitionDescriptor->partitionStartingLocation);
    uint32_t logicalBlockSize          = le32_to_host(pLogicalVolumeDescriptor->logicalBlockSize);

    if (isDirectory(fileIdentifierDescriptor)) {
        cli_dbgmsg("extractFile: Skipping directory\n");
        ret = CL_SUCCESS;
        goto done;
    }

    switch (icbFlags & 3) {
        case 0: {
            if (sizeof(short_ad) != allocation_descriptor_len) {
                cli_warnmsg("extractFile: Short Allocation Descriptor length is incorrect.\n");
                goto done;
            }

            short_ad *shortDesc = (short_ad *)allocation_descriptor;

            offset = partitionStartingLocation * logicalBlockSize;
            offset += le32_to_host(shortDesc->position) * logicalBlockSize;

            length = le32_to_host(shortDesc->length);

        } break;
        case 1: {
            if (sizeof(long_ad) != allocation_descriptor_len) {
                cli_warnmsg("extractFile: Long Allocation Descriptor length is incorrect.\n");
                goto done;
            }

            long_ad *longDesc = (long_ad *)allocation_descriptor;

            offset = partitionStartingLocation * logicalBlockSize;
            length = le32_to_host(longDesc->length);

            if (le16_to_host(longDesc->extentLocation.partitionReferenceNumber) != le16_to_host(pPartitionDescriptor->partitionNumber)) {
                cli_warnmsg("extractFile: Unable to extract the files because the Partition Descriptor Reference Numbers don't match\n");
                goto done;
            }
            offset += le32_to_host(longDesc->extentLocation.blockNumber) * logicalBlockSize;
            offset += partitionStartingLocation;

        } break;
        case 2: {
            if (sizeof(ext_ad) != allocation_descriptor_len) {
                cli_warnmsg("extractFile: Extended Allocation Descriptor length is incorrect.\n");
                goto done;
            }

            ext_ad *extDesc = (ext_ad *)allocation_descriptor;

            offset = partitionStartingLocation * logicalBlockSize;
            length = le32_to_host(extDesc->recordedLen);

            if (le16_to_host(extDesc->extentLocation.partitionReferenceNumber) != le16_to_host(pPartitionDescriptor->partitionNumber)) {
                cli_warnmsg("extractFile: Unable to extract the files because the Partition Descriptor Reference Numbers don't match\n");
                goto done;
            }
            offset += le32_to_host(extDesc->extentLocation.blockNumber) * logicalBlockSize;
            offset += partitionStartingLocation;
        } break;
        default:
            // impossible unless the file is malformed.
            cli_warnmsg("extractFile: Unknown descriptor type found.\n");
            goto done;
    }

    contents = (uint8_t *)fmap_need_off(ctx->fmap, offset, length);
    if (NULL == contents) {
        cli_warnmsg("extractFile: Unable to get offset referenced in the file.\n");
        goto done;
    }

    ret = writeWholeFile(ctx, "", contents, length);

    fmap_unneed_off(ctx->fmap, offset, length);

done:

    return ret;
}

```
Any one of the cases in the `icbFlags & 3` switch can crash the program or read OOB at this point as they all try to dereference the pointer.

To fix this, a check on the `fedDescSize` could be done in `findFileEntries` before adding the pointer into the list via `insertPointer`. If it is too large, do not add and exit the loop.

5.	Proof-of-Concept
  a.	Upload all proof-of-concept code *via file attachment*
  b.	Put any additional instructions or explanation for executing the proof-of-concept here
  c.	Full exploit code is optional

I have uploaded a zip file containing both a reproducer file and the python script to create the reproducer file. On a fresh build of clamav this should result in a crash when scanning against the file.
Note that the python script uses pwntools and python3, so it may be necessary to install before running:
https://docs.pwntools.com/en/stable/install.html#python3

The reproducer works for the most recently released clamav package, this can be found on the github releases page for clamav https://github.com/Cisco-Talos/clamav.
After downloading the package install it with `dpkg -i`, then follow the instructions here to configure clamav: https://docs.clamav.net/manual/Usage/Configuration.html.
After configuration has been completed, simply run: `clamscan <path to udf_tester.udf>`.
This should result in a crash.

Most recently tested on release 1.4.1.

s
6.	Software Download Link
  a.	For vetting purposes

Source code for clamav can be found here:
https://github.com/Cisco-Talos/clamav

Most recent release (1.4.1) for linux x86_64 can be found here: 
https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.4.1
