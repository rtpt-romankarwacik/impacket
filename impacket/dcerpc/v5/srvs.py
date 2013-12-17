# Copyright (c) 2003-2013 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Alberto Solino
#
# Description:
#   [MS-SRVS] Interface implementation
#

from impacket.dcerpc.v5 import ndr
from impacket.dcerpc.v5.ndr import NDRCall, NDR, NDRENUM, NDRUnion, NDRLONG, NDRPointer, NDRUniConformantArray, NDRUniFixedArray, NDRBOOLEAN
from impacket.dcerpc.v5.dtypes import *
from impacket import system_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.enum import Enum

MSRPC_UUID_SRVS  = uuidtup_to_bin(('4B324FC8-1670-01D3-1278-5A47BF6EE188', '3.0'))

class DCERPCSessionError(Exception):
    def __init__( self, packet = None, error_code = None):
        Exception.__init__(self)
        self.packet = packet
        if packet is not None:
            self.error_code = packet['ErrorCode']
        else:
            self.error_code = error_code
       
    def get_error_code( self ):
        return self.error_code
 
    def get_packet( self ):
        return self.packet

    def __str__( self ):
        key = self.error_code
        if (system_errors.ERROR_MESSAGES.has_key(key)):
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'SRVS SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'SRVS SessionError: unknown error code: 0x%x' % (self.error_code)

################################################################################
# CONSTANTS
################################################################################
# 2.2.1.1 SRVSVC_HANDLE
SRVSVC_HANDLE = WCHAR

class PSRVSVC_HANDLE(NDRPointer):
    referent = (
        ('Data', SRVSVC_HANDLE),
    )

# 2.2.1.2 SHARE_DEL_HANDLE
class SHARE_DEL_HANDLE(NDR):
    structure =  (
        ('Data','20s=""'),
    )

# 2.2.1.3 PSHARE_DEL_HANDLE
class PSHARE_DEL_HANDLE(NDRPointer):
    referent = (
        ('Data', SHARE_DEL_HANDLE),
    )

# 2.2.2.2 MAX_PREFERRED_LENGTH
MAX_PREFERRED_LENGTH = -1

# 2.2.2.3 Session User Flags
SESS_GUEST        = 0x00000001
SESS_NOENCRYPTION = 0x00000002

# 2.2.2.4 Share Types
STYPE_DISKTREE     = 0x00000000
STYPE_PRINTQ       = 0x00000001
STYPE_DEVICE       = 0x00000002
STYPE_IPC          = 0x00000003
STYPE_CLUSTER_FS   = 0x02000000
STYPE_CLUSTER_SOFS = 0x04000000
STYPE_CLUSTER_DFS  = 0x08000000

STYPE_SPECIAL      = 0x80000000
STYPE_TEMPORARY    = 0x40000000

# 2.2.2.5 Client-Side Caching (CSC) States
CSC_CACHE_MANUAL_REINT = 0x00
CSC_CACHE_AUTO_REINT   = 0x10
CSC_CACHE_VDO          = 0x20
CSC_CACHE_NONE         = 0x30

# 2.2.2.6 Platform IDs
PLATFORM_ID_DOS = 300
PLATFORM_ID_OS2 = 400
PLATFORM_ID_NT  = 500
PLATFORM_ID_OSF = 600
PLATFORM_ID_VMS = 700

# 2.2.2.7 Software Type Flags
SV_TYPE_WORKSTATION       = 0x00000001
SV_TYPE_SERVER            = 0x00000002
SV_TYPE_SQLSERVER         = 0x00000004
SV_TYPE_DOMAIN_CTRL       = 0x00000008
SV_TYPE_DOMAIN_BAKCTRL    = 0x00000010
SV_TYPE_TIME_SOURCE       = 0x00000020
SV_TYPE_AFP               = 0x00000040
SV_TYPE_NOVELL            = 0x00000080
SV_TYPE_DOMAIN_MEMBER     = 0x00000100
SV_TYPE_LOCAL_LIST_ONLY   = 0x40000000
SV_TYPE_PRINTQ_SERVER     = 0x00000200
SV_TYPE_DIALIN_SERVER     = 0x00000400
SV_TYPE_XENIX_SERVER      = 0x00000800
SV_TYPE_SERVER_MFPN       = 0x00004000
SV_TYPE_NT                = 0x00001000
SV_TYPE_WFW               = 0x00002000
SV_TYPE_SERVER_NT         = 0x00008000
SV_TYPE_POTENTIAL_BROWSER = 0x00010000
SV_TYPE_BACKUP_BROWSER    = 0x00020000
SV_TYPE_MASTER_BROWSER    = 0x00040000
SV_TYPE_DOMAIN_MASTER     = 0x00080000
SV_TYPE_DOMAIN_ENUM       = 0x80000000
SV_TYPE_WINDOWS           = 0x00400000
SV_TYPE_ALL               = 0xFFFFFFFF
SV_TYPE_TERMINALSERVER    = 0x02000000
SV_TYPE_CLUSTER_NT        = 0x10000000
SV_TYPE_CLUSTER_VS_NT     = 0x04000000

# 2.2.2.8 Name Types
NAMETYPE_USER          = 1
NAMETYPE_PASSWORD      = 2
NAMETYPE_GROUP         = 3
NAMETYPE_COMPUTER      = 4
NAMETYPE_EVENT         = 5
NAMETYPE_DOMAIN        = 6
NAMETYPE_SERVICE       = 7
NAMETYPE_NET           = 8
NAMETYPE_SHARE         = 9
NAMETYPE_MESSAGE       = 10
NAMETYPE_MESSAGEDEST   = 11
NAMETYPE_SHAREPASSWORD = 12
NAMETYPE_WORKGROUP     = 13

# 2.2.2.9 Path Types
ITYPE_UNC_COMPNAME     = 4144
ITYPE_UNC_WC           = 4145
ITYPE_UNC              = 4096
ITYPE_UNC_WC_PATH      = 4097
ITYPE_UNC_SYS_SEM      = 6400
ITYPE_UNC_SYS_SHMEM    = 6656
ITYPE_UNC_SYS_MSLOT    = 6144
ITYPE_UNC_SYS_PIPE     = 6912
ITYPE_UNC_SYS_QUEUE    = 7680
ITYPE_PATH_ABSND       = 8194
ITYPE_PATH_ABSD        = 8198
ITYPE_PATH_RELND       = 8192
ITYPE_PATH_RELD        = 8196
ITYPE_PATH_ABSND_WC    = 8195
ITYPE_PATH_ABSD_WC     = 8199
ITYPE_PATH_RELND_WC    = 8193
ITYPE_PATH_RELD_WC     = 8197
ITYPE_PATH_SYS_SEM     = 10498
ITYPE_PATH_SYS_SHMEM   = 10754
ITYPE_PATH_SYS_MSLOT   = 10242
ITYPE_PATH_SYS_PIPE    = 11010
ITYPE_PATH_SYS_COMM    = 11266
ITYPE_PATH_SYS_PRINT   = 11522
ITYPE_PATH_SYS_QUEUE   = 11778
ITYPE_PATH_SYS_SEM_M   = 43266
ITYPE_PATH_SYS_SHMEM_M = 43522
ITYPE_PATH_SYS_MSLOT_M = 43010
ITYPE_PATH_SYS_PIPE_M  = 43778
ITYPE_PATH_SYS_COMM_M  = 44034
ITYPE_PATH_SYS_PRINT_M = 44290
ITYPE_PATH_SYS_QUEUE_M = 44546
ITYPE_DEVICE_DISK      = 16384
ITYPE_DEVICE_LPT       = 16400
ITYPE_DEVICE_COM       = 16416
ITYPE_DEVICE_CON       = 16448
ITYPE_DEVICE_NUL       = 16464

# 2.2.2.11 SHARE_INFO Parameter Error Codes

SHARE_NETNAME_PARMNUM      = 1
SHARE_TYPE_PARMNUM         = 3
SHARE_REMARK_PARMNUM       = 4
SHARE_PERMISSIONS_PARMNUM  = 5
SHARE_MAX_USES_PARMNUM     = 6
SHARE_CURRENT_USES_PARMNUM = 7
SHARE_PATH_PARMNUM         = 8
SHARE_PASSWD_PARMNUM       = 9
SHARE_FILE_SD_PARMNUM      = 501

# 2.2.2.12 SERVER_INFO Parameter Error Codes
SV_PLATFORM_ID_PARMNUM             = 101
SV_NAME_PARMNUM                    = 102
SV_VERSION_MAJOR_PARMNUM           = 103
SV_VERSION_MINOR_PARMNUM           = 104
SV_TYPE_PARMNUM                    = 105
SV_COMMENT_PARMNUM                 = 5
SV_USERS_PARMNUM                   = 107
SV_DISC_PARMNUM                    = 10
SV_HIDDEN_PARMNUM                  = 16
SV_ANNOUNCE_PARMNUM                = 17
SV_ANNDELTA_PARMNUM                = 18
SV_USERPATH_PARMNUM                = 112
SV_SESSOPENS_PARMNUM               = 501
SV_SESSVCS_PARMNUM                 = 502
SV_OPENSEARCH_PARMNUM              = 503
SV_SIZREQBUF_PARMNUM               = 504
SV_INITWORKITEMS_PARMNUM           = 505
SV_MAXWORKITEMS_PARMNUM            = 506
SV_RAWWORKITEMS_PARMNUM            = 507
SV_IRPSTACKSIZE_PARMNUM            = 508
SV_MAXRAWBUFLEN_PARMNUM            = 509
SV_SESSUSERS_PARMNUM               = 510
SV_SESSCONNS_PARMNUM               = 511
SV_MAXNONPAGEDMEMORYUSAGE_PARMNUM  = 512
SV_MAXPAGEDMEMORYUSAGE_PARMNUM     = 513
SV_ENABLESOFTCOMPAT_PARMNUM        = 514
SV_ENABLEFORCEDLOGOFF_PARMNUM      = 515
SV_TIMESOURCE_PARMNUM              = 516
SV_ACCEPTDOWNLEVELAPIS_PARMNUM     = 517
SV_LMANNOUNCE_PARMNUM              = 518
SV_DOMAIN_PARMNUM                  = 519
SV_MAXCOPYREADLEN_PARMNUM          = 520
SV_MAXCOPYWRITELEN_PARMNUM         = 521
SV_MINKEEPSEARCH_PARMNUM           = 522
SV_MAXKEEPSEARCH_PARMNUM           = 523
SV_MINKEEPCOMPLSEARCH_PARMNUM      = 524
SV_MAXKEEPCOMPLSEARCH_PARMNUM      = 525
SV_THREADCOUNTADD_PARMNUM          = 526
SV_NUMBLOCKTHREADS_PARMNUM         = 527
SV_SCAVTIMEOUT_PARMNUM             = 528
SV_MINRCVQUEUE_PARMNUM             = 529
SV_MINFREEWORKITEMS_PARMNUM        = 530
SV_XACTMEMSIZE_PARMNUM             = 531
SV_THREADPRIORITY_PARMNUM          = 532
SV_MAXMPXCT_PARMNUM                = 533
SV_OPLOCKBREAKWAIT_PARMNUM         = 534
SV_OPLOCKBREAKRESPONSEWAIT_PARMNUM = 535
SV_ENABLEOPLOCKS_PARMNUM           = 536
SV_ENABLEOPLOCKFORCECLOSE_PARMNUM  = 537
SV_ENABLEFCBOPENS_PARMNUM          = 538
SV_ENABLERAW_PARMNUM               = 539
SV_ENABLESHAREDNETDRIVES_PARMNUM   = 540
SV_MINFREECONNECTIONS_PARMNUM      = 541
SV_MAXFREECONNECTIONS_PARMNUM      = 542
SV_INITSESSTABLE_PARMNUM           = 543
SV_INITCONNTABLE_PARMNUM           = 544
SV_INITFILETABLE_PARMNUM           = 545
SV_INITSEARCHTABLE_PARMNUM         = 546
SV_ALERTSCHEDULE_PARMNUM           = 547
SV_ERRORTHRESHOLD_PARMNUM          = 548
SV_NETWORKERRORTHRESHOLD_PARMNUM   = 549
SV_DISKSPACETHRESHOLD_PARMNUM      = 550
SV_MAXLINKDELAY_PARMNUM            = 552
SV_MINLINKTHROUGHPUT_PARMNUM       = 553
SV_LINKINFOVALIDTIME_PARMNUM       = 554
SV_SCAVQOSINFOUPDATETIME_PARMNUM   = 555
SV_MAXWORKITEMIDLETIME_PARMNUM     = 556

# 2.2.2.13 DFS Entry Flags
PKT_ENTRY_TYPE_CAIRO          = 0x0001
PKT_ENTRY_TYPE_MACHINE        = 0x0002
PKT_ENTRY_TYPE_NONCAIRO       = 0x0004
PKT_ENTRY_TYPE_LEAFONLY       = 0x0008
PKT_ENTRY_TYPE_OUTSIDE_MY_DOM = 0x0010
PKT_ENTRY_TYPE_INSITE_ONLY    = 0x0020
PKT_ENTRY_TYPE_REFERRAL_SVC   = 0x0080
PKT_ENTRY_TYPE_PERMANENT      = 0x0100
PKT_ENTRY_TYPE_LOCAL          = 0x0400
PKT_ENTRY_TYPE_LOCAL_XPOINT   = 0x0800
PKT_ENTRY_TYPE_MACH_SHARE     = 0x1000
PKT_ENTRY_TYPE_OFFLINE        = 0x2000

# 2.2.4.7 FILE_INFO_3 
# fi3_permissions
PERM_FILE_READ   = 0x00000001
PERM_FILE_WRITE  = 0x00000002
PERM_FILE_CREATE = 0x00000004
ACCESS_EXEC      = 0x00000008
ACCESS_DELETE    = 0x00000010
ACCESS_ATRIB     = 0x00000020
ACCESS_PERM      = 0x00000040

# 2.2.4.29 SHARE_INFO_1005
# shi1005_flags
SHI1005_FLAGS_DFS                         = 0x00000001
SHI1005_FLAGS_DFS_ROOT                    = 0x00000002
CSC_MASK                                  = 0x00000030
SHI1005_FLAGS_RESTRICT_EXCLUSIVE_OPENS    = 0x00000100
SHI1005_FLAGS_FORCE_SHARED_DELETE         = 0x00000200
SHI1005_FLAGS_ALLOW_NAMESPACE_CACHING     = 0x00000400
SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM = 0x00000800
SHI1005_FLAGS_FORCE_LEVELII_OPLOCK        = 0x00001000
SHI1005_FLAGS_ENABLE_HASH                 = 0x00002000
SHI1005_FLAGS_ENABLE_CA                   = 0x00004000
SHI1005_FLAGS_ENCRYPT_DATA                = 0x00008000

# 2.2.4.43 SERVER_INFO_103
# sv103_capabilities
SRV_SUPPORT_HASH_GENERATION = 0x0001
SRV_HASH_GENERATION_ACTIVE  = 0x0002

# 2.2.4.96 SERVER_TRANSPORT_INFO_3
# svti3_flags
SVTI2_REMAP_PIPE_NAMES = 0x00000002
SVTI2_SCOPED_NAME      = 0x00000004

# 2.2.4.109 DFS_SITENAME_INFO
# SiteFlags
DFS_SITE_PRIMARY = 0x00000001

################################################################################
# STRUCTURES
################################################################################
# 2.2.4.1 CONNECTION_INFO_0
class CONNECTION_INFO_0(NDR):
    structure = (
        ('coni0_id', DWORD),
    )

class CONNECTION_INFO_0_ARRAY(NDRUniConformantArray):
    item = CONNECTION_INFO_0

class LPCONNECTION_INFO_0_ARRAY(NDRPointer):
    referent = (
        ('Data', CONNECTION_INFO_0_ARRAY),
    )

# 2.2.4.2 CONNECTION_INFO_1
class CONNECTION_INFO_1(NDR):
    structure = (
        ('coni1_id', DWORD),
        ('coni1_type', DWORD),
        ('coni1_num_opens', DWORD),
        ('coni1_num_users', DWORD),
        ('coni1_time', DWORD),
        ('coni1_username', LPWSTR),
        ('coni1_netname', LPWSTR),
    )

class CONNECTION_INFO_1_ARRAY(NDRUniConformantArray):
    item = CONNECTION_INFO_1

class LPCONNECTION_INFO_1_ARRAY(NDRPointer):
    referent = (
        ('Data', CONNECTION_INFO_1_ARRAY),
    )

# 2.2.4.3 CONNECT_INFO_0_CONTAINER
class CONNECT_INFO_0_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPCONNECTION_INFO_0_ARRAY),
    )

class LPCONNECT_INFO_0_CONTAINER(NDRPointer):
    referent = (
        ('Data', CONNECT_INFO_0_CONTAINER),
    )

# 2.2.4.4 CONNECT_INFO_1_CONTAINER
class CONNECT_INFO_1_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPCONNECTION_INFO_1_ARRAY),
    )

class LPCONNECT_INFO_1_CONTAINER(NDRPointer):
    referent = (
        ('Data', CONNECT_INFO_1_CONTAINER),
    )

# 2.2.3.1 CONNECT_ENUM_UNION
class CONNECT_ENUM_UNION(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        0: ('Level0', LPCONNECT_INFO_0_CONTAINER),
        1: ('Level1', LPCONNECT_INFO_1_CONTAINER),
    }

# 2.2.4.5 CONNECT_ENUM_STRUCT
class CONNECT_ENUM_STRUCT(NDR):
    structure = (
        ('Level', DWORD),
        ('ConnectInfo', CONNECT_ENUM_UNION),
    )

# 2.2.4.6 FILE_INFO_2
class FILE_INFO_2(NDR):
    structure = (
        ('fi2_id', DWORD),
    )

class LPFILE_INFO_2(NDRPointer):
    referent = (
        ('Data', FILE_INFO_2),
    )

class FILE_INFO_2_ARRAY(NDRUniConformantArray):
    item = FILE_INFO_2

class LPFILE_INFO_2_ARRAY(NDRPointer):
    referent = (
        ('Data', FILE_INFO_2_ARRAY),
    )

# 2.2.4.7 FILE_INFO_3
class FILE_INFO_3(NDR):
    structure = (
        ('fi3_id', DWORD),
        ('fi3_permissions', DWORD),
        ('fi3_num_locks', DWORD),
        ('fi3_path_name', LPWSTR),
        ('fi3_username', LPWSTR),
    )

class LPFILE_INFO_3(NDRPointer):
    referent = (
        ('Data', FILE_INFO_3),
    )

class FILE_INFO_3_ARRAY(NDRUniConformantArray):
    item = FILE_INFO_3

class LPFILE_INFO_3_ARRAY(NDRPointer):
    referent = (
        ('Data', FILE_INFO_3_ARRAY),
    )

# 2.2.4.8 FILE_INFO_2_CONTAINER
class FILE_INFO_2_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPFILE_INFO_2_ARRAY),
    )

class LPFILE_INFO_2_CONTAINER(NDRPointer):
    referent = (
        ('Data', FILE_INFO_2_CONTAINER),
    )

# 2.2.4.9 FILE_INFO_3_CONTAINER
class FILE_INFO_3_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPFILE_INFO_3_ARRAY),
    )

class LPFILE_INFO_3_CONTAINER(NDRPointer):
    referent = (
        ('Data', FILE_INFO_3_CONTAINER),
    )

# 2.2.3.2 FILE_ENUM_UNION
class FILE_ENUM_UNION(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        2: ('Level2', LPFILE_INFO_2_CONTAINER),
        3: ('Level3', LPFILE_INFO_3_CONTAINER),
    }

# 2.2.4.10 FILE_ENUM_STRUCT
class FILE_ENUM_STRUCT(NDR):
    structure = (
        ('Level', DWORD),
        ('FileInfo', FILE_ENUM_UNION),
    )

# 2.2.4.11 SESSION_INFO_0
class SESSION_INFO_0(NDR):
    structure = (
        ('sesi0_cname', LPWSTR),
    )

class LPSESSION_INFO_0(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_0),
    )

class SESSION_INFO_0_ARRAY(NDRUniConformantArray):
    item = SESSION_INFO_0

class LPSESSION_INFO_0_ARRAY(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_0_ARRAY),
    )

# 2.2.4.12 SESSION_INFO_1
class SESSION_INFO_1(NDR):
    structure = (
        ('sesi1_cname', LPWSTR),
        ('sesi1_username', LPWSTR),
        ('sesi1_num_opens', DWORD),
        ('sesi1_idle_time', DWORD),
        ('sesi1_user_flags', DWORD),
    )

class LPSESSION_INFO_1(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_1),
    )

class SESSION_INFO_1_ARRAY(NDRUniConformantArray):
    item = SESSION_INFO_1

class LPSESSION_INFO_1_ARRAY(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_1_ARRAY),
    )

# 2.2.4.13 SESSION_INFO_2
class SESSION_INFO_2(NDR):
    structure = (
        ('sesi2_cname', LPWSTR),
        ('sesi2_username', LPWSTR),
        ('sesi2_num_opens', DWORD),
        ('sesi2_time', DWORD),
        ('sesi2_idle_time', DWORD),
        ('sesi2_user_flags', DWORD),
        ('sesi2_cltype_name', LPWSTR),
    )

class LPSESSION_INFO_2(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_2),
    )

class SESSION_INFO_2_ARRAY(NDRUniConformantArray):
    item = SESSION_INFO_2

class LPSESSION_INFO_2_ARRAY(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_2_ARRAY),
    )

# 2.2.4.14 SESSION_INFO_10
class SESSION_INFO_10(NDR):
    structure = (
        ('sesi10_cname', LPWSTR),
        ('sesi10_username', LPWSTR),
        ('sesi10_time', DWORD),
        ('sesi10_idle_time', DWORD),
    )

class LPSESSION_INFO_10(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_10),
    )

class SESSION_INFO_10_ARRAY(NDRUniConformantArray):
    item = SESSION_INFO_10

class LPSESSION_INFO_10_ARRAY(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_10_ARRAY),
    )

# 2.2.4.15 SESSION_INFO_502
class SESSION_INFO_502(NDR):
    structure = (
        ('sesi502_cname', LPWSTR),
        ('sesi502_username', LPWSTR),
        ('sesi502_num_opens', DWORD),
        ('sesi502_time', DWORD),
        ('sesi502_idle_time', DWORD),
        ('sesi502_user_flags', DWORD),
        ('sesi502_cltype_name', LPWSTR),
        ('sesi502_transport', LPWSTR),
    )

class LPSESSION_INFO_502(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_502),
    )

class SESSION_INFO_502_ARRAY(NDRUniConformantArray):
    item = SESSION_INFO_502

class LPSESSION_INFO_502_ARRAY(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_502_ARRAY),
    )

# 2.2.4.16 SESSION_INFO_0_CONTAINER
class SESSION_INFO_0_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSESSION_INFO_0_ARRAY),
    )

class LPSESSION_INFO_0_CONTAINER(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_0_CONTAINER),
    )

# 2.2.4.17 SESSION_INFO_1_CONTAINER
class SESSION_INFO_1_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSESSION_INFO_1_ARRAY),
    )

class LPSESSION_INFO_1_CONTAINER(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_1_CONTAINER),
    )

# 2.2.4.18 SESSION_INFO_2_CONTAINER
class SESSION_INFO_2_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSESSION_INFO_2_ARRAY),
    )

class LPSESSION_INFO_2_CONTAINER(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_2_CONTAINER),
    )

# 2.2.4.19 SESSION_INFO_10_CONTAINER
class SESSION_INFO_10_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSESSION_INFO_10_ARRAY),
    )

class LPSESSION_INFO_10_CONTAINER(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_10_CONTAINER),
    )

# 2.2.4.20 SESSION_INFO_502_CONTAINER
class SESSION_INFO_502_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSESSION_INFO_502_ARRAY),
    )

class LPSESSION_INFO_502_CONTAINER(NDRPointer):
    referent = (
        ('Data', SESSION_INFO_502_CONTAINER),
    )

# 2.2.3.4 SESSION_ENUM_UNION
class SESSION_ENUM_UNION(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        0: ('Level0', LPSESSION_INFO_0_CONTAINER),
        1: ('Level1', LPSESSION_INFO_1_CONTAINER),
        2: ('Level2', LPSESSION_INFO_2_CONTAINER),
        10: ('Level10', LPSESSION_INFO_10_CONTAINER),
        502: ('Level502', LPSESSION_INFO_502_CONTAINER),
    }

# 2.2.4.21 SESSION_ENUM_STRUCT
class SESSION_ENUM_STRUCT(NDR):
    structure = (
        ('Level', DWORD),
        ('SessionInfo', SESSION_ENUM_UNION),
    )

# 2.2.4.22 SHARE_INFO_0
class SHARE_INFO_0(NDR):
    structure = (
        ('shi0_netname', LPWSTR),
    )

class LPSHARE_INFO_0(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_0),
    )

class SHARE_INFO_0_ARRAY(NDRUniConformantArray):
    item = SHARE_INFO_0

class LPSHARE_INFO_0_ARRAY(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_0_ARRAY),
    )

# 2.2.4.23 SHARE_INFO_1
class SHARE_INFO_1(NDR):
    structure = (
        ('shi1_netname', LPWSTR),
        ('shi1_type', DWORD),
        ('shi1_remark', LPWSTR),
    )

class LPSHARE_INFO_1(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_1),
    )

class SHARE_INFO_1_ARRAY(NDRUniConformantArray):
    item = SHARE_INFO_1

class LPSHARE_INFO_1_ARRAY(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_1_ARRAY),
    )

# 2.2.4.24 SHARE_INFO_2
class SHARE_INFO_2(NDR):
    structure = (
        ('shi2_netname', LPWSTR),
        ('shi2_type', DWORD),
        ('shi2_remark', LPWSTR),
        ('shi2_permissions', DWORD),
        ('shi2_max_uses', DWORD),
        ('shi2_current_uses', DWORD),
        ('shi2_path', LPWSTR),
        ('shi2_passwd', LPWSTR),
    )

class LPSHARE_INFO_2(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_2),
    )

class SHARE_INFO_2_ARRAY(NDRUniConformantArray):
    item = SHARE_INFO_2

class LPSHARE_INFO_2_ARRAY(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_2_ARRAY),
    )

# 2.2.4.25 SHARE_INFO_501
class SHARE_INFO_501(NDR):
    structure = (
        ('shi501_netname', LPWSTR),
        ('shi501_type', DWORD),
        ('shi501_remark', LPWSTR),
        ('shi501_flags', DWORD),
    )

class LPSHARE_INFO_501(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_501),
    )

class SHARE_INFO_501_ARRAY(NDRUniConformantArray):
    item = SHARE_INFO_501

class LPSHARE_INFO_501_ARRAY(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_501_ARRAY),
    )

# 2.2.4.26 SHARE_INFO_502_I
class SHARE_INFO_502(NDR):
    structure = (
        ('shi502_netname', LPWSTR),
        ('shi502_type', DWORD),
        ('shi502_remark', LPWSTR),
        ('shi502_permissions', DWORD),
        ('shi502_max_uses', DWORD),
        ('shi502_current_uses', DWORD),
        ('shi502_path', LPWSTR),
        ('shi502_passwd', LPWSTR),
        ('shi502_reserved', DWORD),
        ('shi502_security_descriptor', LPBYTE),
    )

class LPSHARE_INFO_502(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_502),
    )

class SHARE_INFO_502_ARRAY(NDRUniConformantArray):
    item = SHARE_INFO_502

class LPSHARE_INFO_502_ARRAY(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_502_ARRAY),
    )

# 2.2.4.27 SHARE_INFO_503_I
class SHARE_INFO_503(NDR):
    structure = (
        ('shi503_netname', LPWSTR),
        ('shi503_type', DWORD),
        ('shi503_remark', LPWSTR),
        ('shi503_permissions', DWORD),
        ('shi503_max_uses', DWORD),
        ('shi503_current_uses', DWORD),
        ('shi503_path', LPWSTR),
        ('shi503_passwd', LPWSTR),
        ('shi503_servername', LPWSTR),
        ('shi503_reserved', DWORD),
        ('shi503_security_descriptor', LPBYTE),
    )

class LPSHARE_INFO_503(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_503),
    )

class SHARE_INFO_503_ARRAY(NDRUniConformantArray):
    item = SHARE_INFO_503

class LPSHARE_INFO_503_ARRAY(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_503_ARRAY),
    )

# 2.2.4.28 SHARE_INFO_1004
class SHARE_INFO_1004(NDR):
    structure = (
        ('shi1004_remark', LPWSTR),
    )

class LPSHARE_INFO_1004(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_1004),
    )

class SHARE_INFO_1004_ARRAY(NDRUniConformantArray):
    item = SHARE_INFO_1004

class LPSHARE_INFO_1004_ARRAY(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_1004_ARRAY),
    )

# 2.2.4.29 SHARE_INFO_1005
class SHARE_INFO_1005(NDR):
    structure = (
        ('shi1005_flags', DWORD),
    )

class LPSHARE_INFO_1005(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_1005),
    )

class SHARE_INFO_1005_ARRAY(NDRUniConformantArray):
    item = SHARE_INFO_1004

class LPSHARE_INFO_1005_ARRAY(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_1005_ARRAY),
    )

# 2.2.4.30 SHARE_INFO_1006
class SHARE_INFO_1006(NDR):
    structure = (
        ('shi1006_max_uses', DWORD),
    )

class LPSHARE_INFO_1006(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_1006),
    )

class SHARE_INFO_1006_ARRAY(NDRUniConformantArray):
    item = SHARE_INFO_1006

class LPSHARE_INFO_1006_ARRAY(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_1006_ARRAY),
    )

# 2.2.4.31 SHARE_INFO_1501_I
class SHARE_INFO_1501(NDR):
    structure = (
        ('shi1501_reserved', DWORD),
        ('shi1501_security_descriptor', NDRUniConformantArray),
    )

class LPSHARE_INFO_1501(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_1501),
    )

class SHARE_INFO_1501_ARRAY(NDRUniConformantArray):
    item = SHARE_INFO_1501

class LPSHARE_INFO_1501_ARRAY(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_1501_ARRAY),
    )

# 2.2.4.32 SHARE_INFO_0_CONTAINER
class SHARE_INFO_0_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSHARE_INFO_0_ARRAY),
    )

class LPSHARE_INFO_0_CONTAINER(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_0_CONTAINER),
    )

# 2.2.4.33 SHARE_INFO_1_CONTAINER
class SHARE_INFO_1_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSHARE_INFO_1_ARRAY),
    )

class LPSHARE_INFO_1_CONTAINER(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_1_CONTAINER),
    )

# 2.2.4.34 SHARE_INFO_2_CONTAINER
class SHARE_INFO_2_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSHARE_INFO_2_ARRAY),
    )

class LPSHARE_INFO_2_CONTAINER(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_2_CONTAINER),
    )

# 2.2.4.35 SHARE_INFO_501_CONTAINER
class SHARE_INFO_501_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSHARE_INFO_501_ARRAY),
    )

class LPSHARE_INFO_501_CONTAINER(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_501_CONTAINER),
    )

# 2.2.4.36 SHARE_INFO_502_CONTAINER
class SHARE_INFO_502_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSHARE_INFO_502_ARRAY),
    )

class LPSHARE_INFO_502_CONTAINER(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_502_CONTAINER),
    )

# 2.2.4.37 SHARE_INFO_503_CONTAINER
class SHARE_INFO_503_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSHARE_INFO_503_ARRAY),
    )

class LPSHARE_INFO_503_CONTAINER(NDRPointer):
    referent = (
        ('Data', SHARE_INFO_503_CONTAINER),
    )

# 2.2.3.5 SHARE_ENUM_UNION
class SHARE_ENUM_UNION(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        0: ('Level0', LPSHARE_INFO_0_CONTAINER),
        1: ('Level1', LPSHARE_INFO_1_CONTAINER),
        2: ('Level2', LPSHARE_INFO_2_CONTAINER),
        501: ('Level501', LPSHARE_INFO_501_CONTAINER),
        502: ('Level502', LPSHARE_INFO_502_CONTAINER),
        503: ('Level503', LPSHARE_INFO_503_CONTAINER),
    }

# 2.2.4.38 SHARE_ENUM_STRUCT
class SHARE_ENUM_STRUCT(NDR):
    structure = (
        ('Level', DWORD),
        ('ShareInfo', SHARE_ENUM_UNION),
    )

# 2.2.4.39 STAT_SERVER_0
class STAT_SERVER_0(NDR):
    structure = (
        ('sts0_start', DWORD),
        ('sts0_fopens', DWORD),
        ('sts0_devopens', DWORD),
        ('sts0_jobsqueued', DWORD),
        ('sts0_sopens', DWORD),
        ('sts0_stimedout', DWORD),
        ('sts0_serrorout', DWORD),
        ('sts0_pwerrors', DWORD),
        ('sts0_permerrors', DWORD),
        ('sts0_syserrors', DWORD),
        ('sts0_bytessent_low', DWORD),
        ('sts0_bytessent_high', DWORD),
        ('sts0_bytesrcvd_low', DWORD),
        ('sts0_bytesrcvd_high', DWORD),
        ('sts0_avresponse', DWORD),
        ('sts0_reqbufneed', DWORD),
        ('sts0_bigbufneed', DWORD),
    )

# 2.2.4.40 SERVER_INFO_100
class SERVER_INFO_100(NDR):
    structure = (
        ('sv100_platform_id', DWORD),
        ('sv100_name', LPWSTR),
    )

class LPSERVER_INFO_100(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_100),
    )

# 2.2.4.41 SERVER_INFO_101
class SERVER_INFO_101(NDR):
    structure = (
        ('sv101_platform_id', DWORD),
        ('sv101_name', LPWSTR),
        ('sv101_version_major', DWORD),
        ('sv101_version_minor', DWORD),
        ('sv101_type', DWORD),
        ('sv101_comment', LPWSTR),
    )

class LPSERVER_INFO_101(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_101),
    )

# 2.2.4.42 SERVER_INFO_102
class SERVER_INFO_102(NDR):
    structure = (
        ('sv102_platform_id', DWORD),
        ('sv102_name', LPWSTR),
        ('sv102_version_major', DWORD),
        ('sv102_version_minor', DWORD),
        ('sv102_type', DWORD),
        ('sv102_comment', LPWSTR),
        ('sv102_users', DWORD),
        ('sv102_disc', DWORD),
        ('sv102_hidden', DWORD),
        ('sv102_announce', DWORD),
        ('sv102_anndelta', DWORD),
        ('sv102_licenses', DWORD),
        ('sv102_userpath', LPWSTR),
    )

class LPSERVER_INFO_102(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_102),
    )

# 2.2.4.43 SERVER_INFO_103
class SERVER_INFO_103(NDR):
    structure = (
        ('sv103_platform_id', DWORD),
        ('sv103_name', LPWSTR),
        ('sv103_version_major', DWORD),
        ('sv103_version_minor', DWORD),
        ('sv103_type', DWORD),
        ('sv103_comment', LPWSTR),
        ('sv103_users', DWORD),
        ('sv103_disc', DWORD),
        ('sv103_hidden', DWORD),
        ('sv103_announce', DWORD),
        ('sv103_anndelta', DWORD),
        ('sv103_licenses', DWORD),
        ('sv103_userpath', LPWSTR),
        ('sv103_capabilities', DWORD),
    )

class LPSERVER_INFO_103(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_103),
    )

# 2.2.4.44 SERVER_INFO_502
class SERVER_INFO_502(NDR):
    structure = (
        ('sv502_sessopens', DWORD),
        ('sv502_sessvcs', DWORD),
        ('sv502_opensearch', DWORD),
        ('sv502_sizreqbuf', DWORD),
        ('sv502_initworkitems', DWORD),
        ('sv502_maxworkitems', DWORD),
        ('sv502_rawworkitems', DWORD),
        ('sv502_irpstacksize', DWORD),
        ('sv502_maxrawbuflen', DWORD),
        ('sv502_sessusers', DWORD),
        ('sv502_sessconns', DWORD),
        ('sv502_maxpagedmemoryusage', DWORD),
        ('sv502_maxnonpagedmemoryusage', DWORD),
        ('sv502_enablesoftcompat', DWORD),
        ('sv502_enableforcedlogoff', DWORD),
        ('sv502_timesource', DWORD),
        ('sv502_acceptdownlevelapis', DWORD),
        ('sv502_lmannounce', DWORD),
    )

class LPSERVER_INFO_502(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_502),
    )

# 2.2.4.45 SERVER_INFO_503
class SERVER_INFO_503(NDR):
    structure = (
        ('sv503_sessopens', DWORD),
        ('sv503_sessvcs', DWORD),
        ('sv503_opensearch', DWORD),
        ('sv503_sizreqbuf', DWORD),
        ('sv503_initworkitems', DWORD),
        ('sv503_maxworkitems', DWORD),
        ('sv503_rawworkitems', DWORD),
        ('sv503_irpstacksize', DWORD),
        ('sv503_maxrawbuflen', DWORD),
        ('sv503_sessusers', DWORD),
        ('sv503_sessconns', DWORD),
        ('sv503_maxpagedmemoryusage', DWORD),
        ('sv503_maxnonpagedmemoryusage', DWORD),
        ('sv503_enablesoftcompat', DWORD),
        ('sv503_enableforcedlogoff', DWORD),
        ('sv503_timesource', DWORD),
        ('sv503_acceptdownlevelapis', DWORD),
        ('sv503_lmannounce', DWORD),
        ('sv503_domain', LPWSTR),
        ('sv503_maxcopyreadlen', DWORD),
        ('sv503_maxcopywritelen', DWORD),
        ('sv503_minkeepsearch', DWORD),
        ('sv503_maxkeepsearch', DWORD),
        ('sv503_minkeepcomplsearch', DWORD),
        ('sv503_maxkeepcomplsearch', DWORD),
        ('sv503_threadcountadd', DWORD),
        ('sv503_numblockthreads', DWORD),
        ('sv503_scavtimeout', DWORD),
        ('sv503_minrcvqueue', DWORD),
        ('sv503_minfreeworkitems', DWORD),
        ('sv503_xactmemsize', DWORD),
        ('sv503_threadpriority', DWORD),
        ('sv503_maxmpxct', DWORD),
        ('sv503_oplockbreakwait', DWORD),
        ('sv503_oplockbreakresponsewait', DWORD),
        ('sv503_enableoplocks', DWORD),
        ('sv503_enableoplockforceclose', DWORD),
        ('sv503_enablefcbopens', DWORD),
        ('sv503_enableraw', DWORD),
        ('sv503_enablesharednetdrives', DWORD),
        ('sv503_minfreeconnections', DWORD),
        ('sv503_maxfreeconnections', DWORD),
    )

class LPSERVER_INFO_503(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_503),
    )

# 2.2.4.46 SERVER_INFO_599
class SERVER_INFO_599(NDR):
    structure = (
        ('sv599_sessopens', DWORD),
        ('sv599_sessvcs', DWORD),
        ('sv599_opensearch', DWORD),
        ('sv599_sizreqbuf', DWORD),
        ('sv599_initworkitems', DWORD),
        ('sv599_maxworkitems', DWORD),
        ('sv599_rawworkitems', DWORD),
        ('sv599_irpstacksize', DWORD),
        ('sv599_maxrawbuflen', DWORD),
        ('sv599_sessusers', DWORD),
        ('sv599_sessconns', DWORD),
        ('sv599_maxpagedmemoryusage', DWORD),
        ('sv599_maxnonpagedmemoryusage', DWORD),
        ('sv599_enablesoftcompat', DWORD),
        ('sv599_enableforcedlogoff', DWORD),
        ('sv599_timesource', DWORD),
        ('sv599_acceptdownlevelapis', DWORD),
        ('sv599_lmannounce', DWORD),
        ('sv599_domain', LPWSTR),
        ('sv599_maxcopyreadlen', DWORD),
        ('sv599_maxcopywritelen', DWORD),
        ('sv599_minkeepsearch', DWORD),
        ('sv599_maxkeepsearch', DWORD),
        ('sv599_minkeepcomplsearch', DWORD),
        ('sv599_maxkeepcomplsearch', DWORD),
        ('sv599_threadcountadd', DWORD),
        ('sv599_numblockthreads', DWORD),
        ('sv599_scavtimeout', DWORD),
        ('sv599_minrcvqueue', DWORD),
        ('sv599_minfreeworkitems', DWORD),
        ('sv599_xactmemsize', DWORD),
        ('sv599_threadpriority', DWORD),
        ('sv599_maxmpxct', DWORD),
        ('sv599_oplockbreakwait', DWORD),
        ('sv599_oplockbreakresponsewait', DWORD),
        ('sv599_enableoplocks', DWORD),
        ('sv599_enableoplockforceclose', DWORD),
        ('sv599_enablefcbopens', DWORD),
        ('sv599_enableraw', DWORD),
        ('sv599_enablesharednetdrives', DWORD),
        ('sv599_minfreeconnections', DWORD),
        ('sv599_maxfreeconnections', DWORD),
        ('sv599_initsesstable', DWORD),
        ('sv599_initconntable', DWORD),
        ('sv599_initfiletable', DWORD),
        ('sv599_initsearchtable', DWORD),
        ('sv599_alertschedule', DWORD),
        ('sv599_errorthreshold', DWORD),
        ('sv599_networkerrorthreshold', DWORD),
        ('sv599_diskspacethreshold', DWORD),
        ('sv599_reserved', DWORD),
        ('sv599_maxlinkdelay', DWORD),
        ('sv599_minlinkthroughput', DWORD),
        ('sv599_linkinfovalidtime', DWORD),
        ('sv599_scavqosinfoupdatetime', DWORD),
        ('sv599_maxworkitemidletime', DWORD),
    )

class LPSERVER_INFO_599(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_599),
    )

# 2.2.4.47 SERVER_INFO_1005
class SERVER_INFO_1005(NDR):
    structure = (
        ('sv1005_comment', LPWSTR),
    )

class LPSERVER_INFO_1005(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1005),
    )

# 2.2.4.48 SERVER_INFO_1107
class SERVER_INFO_1107(NDR):
    structure = (
        ('sv1107_users', DWORD),
    )

class LPSERVER_INFO_1107(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1107),
    )

# 2.2.4.49 SERVER_INFO_1010
class SERVER_INFO_1010(NDR):
    structure = (
        ('sv1010_disc', DWORD),
    )

class LPSERVER_INFO_1010(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1010),
    )

# 2.2.4.50 SERVER_INFO_1016
class SERVER_INFO_1016(NDR):
    structure = (
        ('sv1016_hidden', DWORD),
    )

class LPSERVER_INFO_1016(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1016),
    )

# 2.2.4.51 SERVER_INFO_1017
class SERVER_INFO_1017(NDR):
    structure = (
        ('sv1017_announce', DWORD),
    )

class LPSERVER_INFO_1017(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1017),
    )

# 2.2.4.52 SERVER_INFO_1018
class SERVER_INFO_1018(NDR):
    structure = (
        ('sv1018_anndelta', DWORD),
    )

class LPSERVER_INFO_1018(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1018),
    )

# 2.2.4.53 SERVER_INFO_1501
class SERVER_INFO_1501(NDR):
    structure = (
        ('sv1501_sessopens', DWORD),
    )

class LPSERVER_INFO_1501(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1501),
    )

# 2.2.4.54 SERVER_INFO_1502
class SERVER_INFO_1502(NDR):
    structure = (
        ('sv1502_sessvcs', DWORD),
    )

class LPSERVER_INFO_1502(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1502),
    )

# 2.2.4.55 SERVER_INFO_1503
class SERVER_INFO_1503(NDR):
    structure = (
        ('sv1503_opensearch', DWORD),
    )

class LPSERVER_INFO_1503(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1503),
    )

# 2.2.4.56 SERVER_INFO_1506
class SERVER_INFO_1506(NDR):
    structure = (
        ('sv1506_maxworkitems', DWORD),
    )

class LPSERVER_INFO_1506(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1506),
    )

# 2.2.4.57 SERVER_INFO_1510
class SERVER_INFO_1510(NDR):
    structure = (
        ('sv1510_sessusers', DWORD),
    )

class LPSERVER_INFO_1510(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1510),
    )

# 2.2.4.58 SERVER_INFO_1511
class SERVER_INFO_1511(NDR):
    structure = (
        ('sv1511_sessconns', DWORD),
    )

class LPSERVER_INFO_1511(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1511),
    )

# 2.2.4.59 SERVER_INFO_1512
class SERVER_INFO_1512(NDR):
    structure = (
        ('sv1512_maxnonpagedmemoryusage', DWORD),
    )

class LPSERVER_INFO_1512(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1512),
    )

# 2.2.4.60 SERVER_INFO_1513
class SERVER_INFO_1513(NDR):
    structure = (
        ('sv1513_maxpagedmemoryusage', DWORD),
    )

class LPSERVER_INFO_1513(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1513),
    )

# 2.2.4.61 SERVER_INFO_1514
class SERVER_INFO_1514(NDR):
    structure = (
        ('sv1514_enablesoftcompat', DWORD),
    )

class LPSERVER_INFO_1514(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1514),
    )

# 2.2.4.62 SERVER_INFO_1515
class SERVER_INFO_1515(NDR):
    structure = (
        ('sv1515_enableforcedlogoff', DWORD),
    )

class LPSERVER_INFO_1515(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1515),
    )

# 2.2.4.63 SERVER_INFO_1516
class SERVER_INFO_1516(NDR):
    structure = (
        ('sv1516_timesource', DWORD),
    )

class LPSERVER_INFO_1516(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1516),
    )

# 2.2.4.64 SERVER_INFO_1518
class SERVER_INFO_1518(NDR):
    structure = (
        ('sv1518_lmannounce', DWORD),
    )

class LPSERVER_INFO_1518(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1518),
    )

# 2.2.4.65 SERVER_INFO_1523
class SERVER_INFO_1523(NDR):
    structure = (
        ('sv1523_maxkeepsearch', DWORD),
    )

class LPSERVER_INFO_1523(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1523),
    )

# 2.2.4.66 SERVER_INFO_1528
class SERVER_INFO_1528(NDR):
    structure = (
        ('sv1528_scavtimeout', DWORD),
    )

class LPSERVER_INFO_1528(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1528),
    )

# 2.2.4.67 SERVER_INFO_1529
class SERVER_INFO_1529(NDR):
    structure = (
        ('sv1529_minrcvqueue', DWORD),
    )

class LPSERVER_INFO_1529(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1529),
    )

# 2.2.4.68 SERVER_INFO_1530
class SERVER_INFO_1530(NDR):
    structure = (
        ('sv1530_minfreeworkitems', DWORD),
    )

class LPSERVER_INFO_1530(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1530),
    )

# 2.2.4.69 SERVER_INFO_1533
class SERVER_INFO_1533(NDR):
    structure = (
        ('sv1533_maxmpxct', DWORD),
    )

class LPSERVER_INFO_1533(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1533),
    )

# 2.2.4.70 SERVER_INFO_1534
class SERVER_INFO_1534(NDR):
    structure = (
        ('sv1534_oplockbreakwait', DWORD),
    )

class LPSERVER_INFO_1534(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1534),
    )

# 2.2.4.71 SERVER_INFO_1535
class SERVER_INFO_1535(NDR):
    structure = (
        ('sv1535_oplockbreakresponsewait', DWORD),
    )

class LPSERVER_INFO_1535(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1535),
    )

# 2.2.4.72 SERVER_INFO_1536
class SERVER_INFO_1536(NDR):
    structure = (
        ('sv1536_enableoplocks', DWORD),
    )

class LPSERVER_INFO_1536(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1536),
    )

# 2.2.4.73 SERVER_INFO_1538
class SERVER_INFO_1538(NDR):
    structure = (
        ('sv1538_enablefcbopens', DWORD),
    )

class LPSERVER_INFO_1538(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1538),
    )

# 2.2.4.74 SERVER_INFO_1539
class SERVER_INFO_1539(NDR):
    structure = (
        ('sv1539_enableraw', DWORD),
    )

class LPSERVER_INFO_1539(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1539),
    )

# 2.2.4.75 SERVER_INFO_1540
class SERVER_INFO_1540(NDR):
    structure = (
        ('sv1540_enablesharednetdrives', DWORD),
    )

class LPSERVER_INFO_1540(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1540),
    )

# 2.2.4.76 SERVER_INFO_1541
class SERVER_INFO_1541(NDR):
    structure = (
        ('sv1541_minfreeconnections', DWORD),
    )

class LPSERVER_INFO_1541(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1541),
    )

# 2.2.4.77 SERVER_INFO_1542
class SERVER_INFO_1542(NDR):
    structure = (
        ('sv1542_maxfreeconnections', DWORD),
    )

class LPSERVER_INFO_1542(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1542),
    )

# 2.2.4.78 SERVER_INFO_1543
class SERVER_INFO_1543(NDR):
    structure = (
        ('sv1543_initsesstable', DWORD),
    )

class LPSERVER_INFO_1543(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1543),
    )

# 2.2.4.79 SERVER_INFO_1544
class SERVER_INFO_1544(NDR):
    structure = (
        ('sv1544_initconntable', DWORD),
    )

class LPSERVER_INFO_1544(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1544),
    )

# 2.2.4.80 SERVER_INFO_1545
class SERVER_INFO_1545(NDR):
    structure = (
        ('sv1545_initfiletable', DWORD),
    )

class LPSERVER_INFO_1545(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1545),
    )

# 2.2.4.81 SERVER_INFO_1546
class SERVER_INFO_1546(NDR):
    structure = (
        ('sv1546_initsearchtable', DWORD),
    )

class LPSERVER_INFO_1546(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1546),
    )

# 2.2.4.82 SERVER_INFO_1547
class SERVER_INFO_1547(NDR):
    structure = (
        ('sv1547_alertschedule', DWORD),
    )

class LPSERVER_INFO_1547(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1547),
    )

# 2.2.4.83 SERVER_INFO_1548
class SERVER_INFO_1548(NDR):
    structure = (
        ('sv1548_errorthreshold', DWORD),
    )

class LPSERVER_INFO_1548(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1548),
    )

# 2.2.4.84 SERVER_INFO_1549
class SERVER_INFO_1549(NDR):
    structure = (
        ('sv1549_networkerrorthreshold', DWORD),
    )

class LPSERVER_INFO_1549(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1549),
    )

# 2.2.4.85 SERVER_INFO_1550
class SERVER_INFO_1550(NDR):
    structure = (
        ('sv1550_diskspacethreshold', DWORD),
    )

class LPSERVER_INFO_1550(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1550),
    )

# 2.2.4.86 SERVER_INFO_1552
class SERVER_INFO_1552(NDR):
    structure = (
        ('sv1552_maxlinkdelay', DWORD),
    )

class LPSERVER_INFO_1552(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1552),
    )

# 2.2.4.87 SERVER_INFO_1553
class SERVER_INFO_1553(NDR):
    structure = (
        ('sv1553_minlinkthroughput', DWORD),
    )

class LPSERVER_INFO_1553(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1553),
    )

# 2.2.4.88 SERVER_INFO_1554
class SERVER_INFO_1554(NDR):
    structure = (
        ('sv1554_linkinfovalidtime', DWORD),
    )

class LPSERVER_INFO_1554(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1554),
    )

# 2.2.4.89 SERVER_INFO_1555
class SERVER_INFO_1555(NDR):
    structure = (
        ('sv1555_scavqosinfoupdatetime', DWORD),
    )

class LPSERVER_INFO_1555(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1555),
    )

# 2.2.4.90 SERVER_INFO_1556
class SERVER_INFO_1556(NDR):
    structure = (
        ('sv1556_maxworkitemidletime', DWORD),
    )

class LPSERVER_INFO_1556(NDRPointer):
    referent = (
        ('Data', SERVER_INFO_1556),
    )

# 2.2.4.91 DISK_INFO
class DISK_INFO(NDR):
    structure = (
        ('Disk', WSTR),
    )

class LPDISK_INFO(NDRPointer):
    referent = (
        ('Data', DISK_INFO),
    )

class DISK_INFO_ARRAY(NDRUniConformantArray):
    item = DISK_INFO

class LPDISK_INFO_ARRAY(NDRPointer):
    referent = (
        ('Data', DISK_INFO_ARRAY),
    )

# 2.2.4.92 DISK_ENUM_CONTAINER
class DISK_ENUM_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPDISK_INFO_ARRAY),
    )

class LPDISK_ENUM_CONTAINER(NDRPointer):
    referent = (
        ('Data', DISK_ENUM_CONTAINER),
    )

# 2.2.4.93 SERVER_TRANSPORT_INFO_0
class SERVER_TRANSPORT_INFO_0(NDR):
    structure = (
        ('svti0_numberofvcs', DWORD),
        ('svti0_transportname', LPWSTR),
        ('svti0_transportaddress', NDRUniConformantArray),
        ('svti0_transportaddresslength', DWORD),
        ('svti0_networkaddress', LPWSTR),
    )

class LPSERVER_TRANSPORT_INFO_0(NDRPointer):
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_0),
    )

class SERVER_TRANSPORT_INFO_0_ARRAY(NDRUniConformantArray):
    item = SERVER_TRANSPORT_INFO_0

class LPSERVER_TRANSPORT_INFO_0_ARRAY(NDRPointer):
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_0_ARRAY),
    )

# 2.2.4.94 SERVER_TRANSPORT_INFO_1
class SERVER_TRANSPORT_INFO_1(NDR):
    structure = (
        ('svti1_numberofvcs', DWORD),
        ('svti1_transportname', LPWSTR),
        ('svti1_transportaddress', NDRUniConformantArray),
        ('svti1_transportaddresslength', DWORD),
        ('svti1_networkaddress', LPWSTR),
        ('svti1_domain', LPWSTR),
    )

class LPSERVER_TRANSPORT_INFO_1(NDRPointer):
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_1),
    )

class SERVER_TRANSPORT_INFO_1_ARRAY(NDRUniConformantArray):
    item = SERVER_TRANSPORT_INFO_1

class LPSERVER_TRANSPORT_INFO_1_ARRAY(NDRPointer):
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_1_ARRAY),
    )

# 2.2.4.95 SERVER_TRANSPORT_INFO_2
class SERVER_TRANSPORT_INFO_2(NDR):
    structure = (
        ('svti2_numberofvcs', DWORD),
        ('svti2_transportname', LPWSTR),
        ('svti2_transportaddress', NDRUniConformantArray),
        ('svti2_transportaddresslength', DWORD),
        ('svti2_networkaddress', LPWSTR),
        ('svti2_domain', LPWSTR),
        ('svti2_flags', DWORD),
    )

class LPSERVER_TRANSPORT_INFO_2(NDRPointer):
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_2),
    )

class SERVER_TRANSPORT_INFO_2_ARRAY(NDRUniConformantArray):
    item = SERVER_TRANSPORT_INFO_2

class LPSERVER_TRANSPORT_INFO_2_ARRAY(NDRPointer):
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_2_ARRAY),
    )

# 2.2.4.96 SERVER_TRANSPORT_INFO_3
class PASSWORD_ARRAY(NDRUniFixedArray):
    def getDataLen(self, data):
        return 256

class SERVER_TRANSPORT_INFO_3(NDR):
    structure = (
        ('svti3_numberofvcs', DWORD),
        ('svti3_transportname', LPWSTR),
        ('svti3_transportaddress', NDRUniConformantArray),
        ('svti3_transportaddresslength', DWORD),
        ('svti3_networkaddress', LPWSTR),
        ('svti3_domain', LPWSTR),
        ('svti3_flags', DWORD),
        ('svti3_passwordlength', DWORD),
        ('svti3_password', PASSWORD_ARRAY),
    )

class LPSERVER_TRANSPORT_INFO_3(NDRPointer):
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_3),
    )

class SERVER_TRANSPORT_INFO_3_ARRAY(NDRUniConformantArray):
    item = SERVER_TRANSPORT_INFO_3

class LPSERVER_TRANSPORT_INFO_3_ARRAY(NDRPointer):
    referent = (
        ('Data', SERVER_TRANSPORT_INFO_3_ARRAY),
    )

# 2.2.4.97 SERVER_XPORT_INFO_0_CONTAINER
class SERVER_XPORT_INFO_0_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSERVER_TRANSPORT_INFO_0_ARRAY),
    )

class LPSERVER_XPORT_INFO_0_CONTAINER(NDRPointer):
    referent = (
        ('Data', SERVER_XPORT_INFO_0_CONTAINER),
    )

# 2.2.4.98 SERVER_XPORT_INFO_1_CONTAINER
class SERVER_XPORT_INFO_1_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSERVER_TRANSPORT_INFO_1_ARRAY),
    )

class LPSERVER_XPORT_INFO_1_CONTAINER(NDRPointer):
    referent = (
        ('Data', SERVER_XPORT_INFO_1_CONTAINER),
    )

# 2.2.4.99 SERVER_XPORT_INFO_2_CONTAINER
class SERVER_XPORT_INFO_2_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSERVER_TRANSPORT_INFO_2_ARRAY),
    )

class LPSERVER_XPORT_INFO_2_CONTAINER(NDRPointer):
    referent = (
        ('Data', SERVER_XPORT_INFO_2_CONTAINER),
    )

# 2.2.4.100 SERVER_XPORT_INFO_3_CONTAINER
class SERVER_XPORT_INFO_3_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSERVER_TRANSPORT_INFO_3_ARRAY),
    )

class LPSERVER_XPORT_INFO_3_CONTAINER(NDRPointer):
    referent = (
        ('Data', SERVER_XPORT_INFO_3_CONTAINER),
    )

# 2.2.3.8 SERVER_XPORT_ENUM_UNION
class SERVER_XPORT_ENUM_UNION(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        0: ('Level0', LPSERVER_XPORT_INFO_0_CONTAINER),
        1: ('Level1', LPSERVER_XPORT_INFO_1_CONTAINER),
        2: ('Level2', LPSERVER_XPORT_INFO_2_CONTAINER),
        3: ('Level3', LPSERVER_XPORT_INFO_3_CONTAINER),
    }

# 2.2.4.101 SERVER_XPORT_ENUM_STRUCT
class SERVER_XPORT_ENUM_STRUCT(NDR):
    structure = (
        ('Level', DWORD),
        ('XportInfo', SERVER_XPORT_ENUM_UNION),
    )

# 2.2.4.102 SERVER_ALIAS_INFO_0
class SERVER_ALIAS_INFO_0(NDR):
    structure = (
        ('srvai0_alias', LMSTR),
        ('srvai0_target', LMSTR),
        ('srvai0_default', NDRBOOLEAN),
        ('srvai0_reserved', ULONG),
    )

class LPSERVER_ALIAS_INFO_0(NDRPointer):
    referent = (
        ('Data', SERVER_ALIAS_INFO_0),
    )

class SERVER_ALIAS_INFO_0_ARRAY(NDRUniConformantArray):
    item = SERVER_ALIAS_INFO_0

class LPSERVER_ALIAS_INFO_0_ARRAY(NDRPointer):
    referent = (
        ('Data', SERVER_ALIAS_INFO_0_ARRAY),
    )

# 2.2.4.103 SERVER_ALIAS_INFO_0_CONTAINER
class SERVER_ALIAS_INFO_0_CONTAINER(NDR):
    structure = (
        ('EntriesRead', DWORD),
        ('Buffer', LPSERVER_ALIAS_INFO_0_ARRAY),
    )

class LPSERVER_ALIAS_INFO_0_CONTAINER(NDRPointer):
    referent = (
        ('Data', SERVER_ALIAS_INFO_0_CONTAINER),
    )

# 2.2.4.104 SERVER_ALIAS_ENUM_STRUCT
class SERVER_ALIAS_ENUM_UNION(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        0: ('Level0', LPSERVER_ALIAS_INFO_0_CONTAINER),
    }

class SERVER_ALIAS_ENUM_STRUCT(NDR):
    structure = (
        ('Level', DWORD),
        ('ServerAliasInfo', SERVER_ALIAS_ENUM_UNION),
    )

# 2.2.4.105 TIME_OF_DAY_INFO
class TIME_OF_DAY_INFO(NDR):
    structure = (
        ('tod_elapsedt', DWORD),
        ('tod_msecs', DWORD),
        ('tod_hours', DWORD),
        ('tod_mins', DWORD),
        ('tod_secs', DWORD),
        ('tod_hunds', DWORD),
        ('tod_timezone', DWORD),
        ('tod_tinterval', DWORD),
        ('tod_day', DWORD),
        ('tod_month', DWORD),
        ('tod_year', DWORD),
        ('tod_weekday', DWORD),
    )

# 2.2.4.106 ADT_SECURITY_DESCRIPTOR
class ADT_SECURITY_DESCRIPTOR(NDR):
    structure = (
        ('Length', DWORD),
        ('Buffer', NDRUniConformantArray),
    )

# 2.2.4.107 NET_DFS_ENTRY_ID
class NET_DFS_ENTRY_ID(NDR):
    structure = (
        ('Uid', GUID),
        ('Prefix', LPWSTR),
    )

class NET_DFS_ENTRY_ID_ARRAY(NDRUniConformantArray):
    item = NET_DFS_ENTRY_ID

class LPNET_DFS_ENTRY_ID_ARRAY(NDRPointer):
     referent = (
         ('Data', NET_DFS_ENTRY_ID_ARRAY),
     )

# 2.2.4.108 NET_DFS_ENTRY_ID_CONTAINER
class NET_DFS_ENTRY_ID_CONTAINER(NDR):
    structure = (
        ('Count', GUID),
        ('Buffer', LPNET_DFS_ENTRY_ID_ARRAY),
    )

# 2.2.4.109 DFS_SITENAME_INFO
class DFS_SITENAME_INFO(NDR):
    structure = (
        ('SiteFlags', DWORD),
        ('SiteName', LPWSTR),
    )

# 2.2.4.110 DFS_SITELIST_INFO
class DFS_SITENAME_INFO_ARRAY(NDRUniConformantArray):
    item = DFS_SITENAME_INFO

class DFS_SITELIST_INFO(NDR):
    structure = (
        ('cSites', DWORD),
        ('Site', DFS_SITENAME_INFO_ARRAY),
    )

# 2.2.3 Unions
# 2.2.3.3 FILE_INFO
class FILE_INFO(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        2: ('FileInfo2', LPFILE_INFO_2),
        3: ('FileInfo3', LPFILE_INFO_3),
    }

# 2.2.3.6 SHARE_INFO
class SHARE_INFO(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        0: ('ShareInfo0', LPSHARE_INFO_0),
        1: ('ShareInfo1', LPSHARE_INFO_1),
        2: ('ShareInfo2', LPSHARE_INFO_2),
        502: ('ShareInfo502', LPSHARE_INFO_502),
        1004: ('ShareInfo1004', LPSHARE_INFO_1004),
        1006: ('ShareInfo1006', LPSHARE_INFO_1006),
        1501: ('ShareInfo1501', LPSHARE_INFO_1501),
        1005: ('ShareInfo1005', LPSHARE_INFO_1005),
        501: ('ShareInfo501', LPSHARE_INFO_501),
        503: ('ShareInfo503', LPSHARE_INFO_503),
    }

# 2.2.3.7 SERVER_INFO
class SERVER_INFO(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        100: ('ServerInfo100', LPSERVER_INFO_100),
        101: ('ServerInfo101', LPSERVER_INFO_101),
        102: ('ServerInfo102', LPSERVER_INFO_102),
        103: ('ServerInfo103', LPSERVER_INFO_103),
        502: ('ServerInfo502', LPSERVER_INFO_502),
        503: ('ServerInfo503', LPSERVER_INFO_503),
        599: ('ServerInfo599', LPSERVER_INFO_599),
        1005: ('ServerInfo1005', LPSERVER_INFO_1005),
        1107: ('ServerInfo1107', LPSERVER_INFO_1107),
        1010: ('ServerInfo1010', LPSERVER_INFO_1010),
        1016: ('ServerInfo1016', LPSERVER_INFO_1016),
        1017: ('ServerInfo1017', LPSERVER_INFO_1017),
        1018: ('ServerInfo1018', LPSERVER_INFO_1018),
        1501: ('ServerInfo1501', LPSERVER_INFO_1501),
        1502: ('ServerInfo1502', LPSERVER_INFO_1502),
        1503: ('ServerInfo1503', LPSERVER_INFO_1503),
        1506: ('ServerInfo1506', LPSERVER_INFO_1506),
        1510: ('ServerInfo1510', LPSERVER_INFO_1510),
        1511: ('ServerInfo1511', LPSERVER_INFO_1511),
        1512: ('ServerInfo1512', LPSERVER_INFO_1512),
        1513: ('ServerInfo1513', LPSERVER_INFO_1513),
        1514: ('ServerInfo1514', LPSERVER_INFO_1514),
        1515: ('ServerInfo1515', LPSERVER_INFO_1515),
        1516: ('ServerInfo1516', LPSERVER_INFO_1516),
        1518: ('ServerInfo1518', LPSERVER_INFO_1518),
        1523: ('ServerInfo1523', LPSERVER_INFO_1523),
        1528: ('ServerInfo1528', LPSERVER_INFO_1528),
        1529: ('ServerInfo1529', LPSERVER_INFO_1529),
        1530: ('ServerInfo1530', LPSERVER_INFO_1530),
        1533: ('ServerInfo1533', LPSERVER_INFO_1533),
        1534: ('ServerInfo1534', LPSERVER_INFO_1534),
        1535: ('ServerInfo1535', LPSERVER_INFO_1535),
        1536: ('ServerInfo1536', LPSERVER_INFO_1536),
        1538: ('ServerInfo1538', LPSERVER_INFO_1538),
        1539: ('ServerInfo1539', LPSERVER_INFO_1539),
        1540: ('ServerInfo1540', LPSERVER_INFO_1540),
        1541: ('ServerInfo1541', LPSERVER_INFO_1541),
        1542: ('ServerInfo1542', LPSERVER_INFO_1542),
        1543: ('ServerInfo1543', LPSERVER_INFO_1543),
        1544: ('ServerInfo1544', LPSERVER_INFO_1544),
        1545: ('ServerInfo1545', LPSERVER_INFO_1545),
        1546: ('ServerInfo1546', LPSERVER_INFO_1546),
        1547: ('ServerInfo1547', LPSERVER_INFO_1547),
        1548: ('ServerInfo1548', LPSERVER_INFO_1548),
        1549: ('ServerInfo1549', LPSERVER_INFO_1549),
        1550: ('ServerInfo1550', LPSERVER_INFO_1550),
        1552: ('ServerInfo1552', LPSERVER_INFO_1552),
        1553: ('ServerInfo1553', LPSERVER_INFO_1553),
        1554: ('ServerInfo1554', LPSERVER_INFO_1554),
        1555: ('ServerInfo1555', LPSERVER_INFO_1555),
        1556: ('ServerInfo1556', LPSERVER_INFO_1556),
    }

# 2.2.3.9 TRANSPORT_INFO
class TRANSPORT_INFO(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        0: ('Transport0', SERVER_TRANSPORT_INFO_0),
        1: ('Transport1', SERVER_TRANSPORT_INFO_1),
        2: ('Transport2', SERVER_TRANSPORT_INFO_2),
        3: ('Transport3', SERVER_TRANSPORT_INFO_3),
    }

# 2.2.3.10 SERVER_ALIAS_INFO
class SERVER_ALIAS_INFO(NDRUnion):
    align = 4
    commonHdr = (
        ('tag', DWORD),
    )

    union = {
        0: ('ServerAliasInfo0', LPSERVER_ALIAS_INFO_0),
    }


################################################################################
# RPC CALLS
################################################################################
# 3.1.4.1 NetrConnectionEnum (Opnum 8)
class NetrConnectionEnum(NDRCall):
    opnum = 8
    structure = (
       ('ServerName', PSRVSVC_HANDLE),
       ('Qualifier', LPWSTR),
       ('InfoStruct', CONNECT_ENUM_STRUCT),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    )

class NetrConnectionEnumResponse(NDRCall):
    structure = (
       ('InfoStruct',CONNECT_ENUM_STRUCT),
       ('TotalEntries',DWORD),
       ('ResumeHandle',LPLONG),
       ('ErrorCode',NDRLONG),
    )

# 3.1.4.2 NetrFileEnum (Opnum 9)
class NetrFileEnum(NDRCall):
    opnum = 9
    structure = (
       ('ServerName', PSRVSVC_HANDLE),
       ('BasePath', LPWSTR),
       ('UserName', LPWSTR),
       ('InfoStruct', FILE_ENUM_STRUCT),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    )

class NetrFileEnumResponse(NDRCall):
    structure = (
       ('InfoStruct',FILE_ENUM_STRUCT),
       ('TotalEntries',DWORD),
       ('ResumeHandle',LPLONG),
       ('ErrorCode',NDRLONG),
    )

# 3.1.4.3 NetrFileGetInfo (Opnum 10)
class NetrFileGetInfo(NDRCall):
    opnum = 10
    structure = (
       ('ServerName', PSRVSVC_HANDLE),
       ('FileId', DWORD),
       ('Level', DWORD),
    )

class NetrFileGetInfoResponse(NDRCall):
    structure = (
       ('InfoStruct',FILE_INFO),
       ('ErrorCode',NDRLONG),
    )

# 3.1.4.4 NetrFileClose (Opnum 11)
class NetrFileClose(NDRCall):
    opnum = 11
    structure = (
       ('ServerName', PSRVSVC_HANDLE),
       ('FileId', DWORD),
    )

class NetrFileCloseResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

# 3.1.4.5 NetrSessionEnum (Opnum 12)
class NetrSessionEnum(NDRCall):
    opnum = 12
    structure = (
       ('ServerName', PSRVSVC_HANDLE),
       ('ClientName', LPWSTR),
       ('UserName', LPWSTR),
       ('InfoStruct', SESSION_ENUM_STRUCT),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    )

class NetrSessionEnumResponse(NDRCall):
    structure = (
       ('InfoStruct',SESSION_ENUM_STRUCT),
       ('TotalEntries',DWORD),
       ('ResumeHandle',LPLONG),
       ('ErrorCode',NDRLONG),
    )

# 3.1.4.6 NetrSessionDel (Opnum 13)
class NetrSessionDel(NDRCall):
    opnum = 13
    structure = (
       ('ServerName', PSRVSVC_HANDLE),
       ('ClientName', LPWSTR),
       ('UserName', LPWSTR),
    )

class NetrSessionDelResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

# 3.1.4.7 NetrShareAdd (Opnum 14)
class NetrShareAdd(NDRCall):
    opnum = 14
    structure = (
       ('ServerName', PSRVSVC_HANDLE),
       ('Level', DWORD),
       ('InfoStruct', SHARE_INFO),
       ('ParmErr', LPLONG),
    )

class NetrShareAddResponse(NDRCall):
    structure = (
       ('ParmErr', LPLONG),
       ('ErrorCode',NDRLONG),
    )

# 3.1.4.8 NetrShareEnum (Opnum 15)
class NetrShareEnum(NDRCall):
    opnum = 15
    structure = (
       ('ServerName', PSRVSVC_HANDLE),
       ('InfoStruct', SHARE_ENUM_STRUCT),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    )

class NetrShareEnumResponse(NDRCall):
    structure = (
       ('InfoStruct', SHARE_ENUM_STRUCT),
       ('TotalEntries',DWORD),
       ('ResumeHandle',LPLONG),
       ('ErrorCode',NDRLONG),
    )

# 3.1.4.9 NetrShareEnumSticky (Opnum 36)
class NetrShareEnumSticky(NDRCall):
    opnum = 36
    structure = (
       ('ServerName', PSRVSVC_HANDLE),
       ('InfoStruct', SHARE_ENUM_STRUCT),
       ('PreferedMaximumLength', DWORD),
       ('ResumeHandle', LPLONG),
    )

class NetrShareEnumStickyResponse(NDRCall):
    structure = (
       ('InfoStruct', SHARE_ENUM_STRUCT),
       ('TotalEntries',DWORD),
       ('ResumeHandle',LPLONG),
       ('ErrorCode',NDRLONG),
    )

# 3.1.4.10 NetrShareGetInfo (Opnum 16)
class NetrShareGetInfo(NDRCall):
    opnum = 16
    structure = (
       ('ServerName', PSRVSVC_HANDLE),
       ('NetName', WSTR),
       ('Level', DWORD),
    )

class NetrShareGetInfoResponse(NDRCall):
    structure = (
       ('InfoStruct', SHARE_INFO),
       ('ErrorCode',NDRLONG),
    )

# 3.1.4.12 NetrShareDel (Opnum 18)
class NetrShareDel(NDRCall):
    opnum = 18
    structure = (
       ('ServerName', PSRVSVC_HANDLE),
       ('NetName', WSTR),
       ('Reserved', DWORD),
    )

class NetrShareDelResponse(NDRCall):
    structure = (
       ('ErrorCode',NDRLONG),
    )

################################################################################
# HELPER FUNCTIONS
################################################################################
