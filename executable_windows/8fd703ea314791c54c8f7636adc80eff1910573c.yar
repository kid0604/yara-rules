import "pe"

rule mal_host2_143
{
	meta:
		description = "mal - file 143.dll"
		author = "TheDFIRReport"
		date = "2021-11-29"
		hash1 = "6f844a6e903aa8e305e88ac0f60328c184f71a4bfbe93124981d6a4308b14610"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii
		$x2 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
		$x3 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAcceptExSockaddrsGetCurrentDirectoryWGetFileA" ascii
		$x4 = "Go pointer stored into non-Go memoryUnable to determine system directoryaccessing a corrupted shared libraryruntime: VirtualQuer" ascii
		$x5 = "GetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWSetEndOfFileTransmitFileabi mismatchadvapi32" ascii
		$x6 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii
		$x7 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing= ms clock" ascii
		$x8 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
		$x9 = ".lib section in a.out corruptedbad write barrier buffer boundscall from within the Go runtimecannot assign requested addresscasg" ascii
		$x10 = "Ptrmask.lockentersyscallblockexec format errorg already scannedglobalAlloc.mutexlocked m0 woke upmark - bad statusmarkBits overf" ascii
		$x11 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii
		$x12 = "ollectionidentifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation c" ascii
		$s13 = "y failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime: invalid typeBitsBulkBarrierrunt" ascii
		$s14 = "ddetailsecur32.dllshell32.dlltracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  found at *( gcscandone  m->gs" ascii
		$s15 = ".dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend tracegc" fullword ascii
		$s16 = "ked to threadCommandLineToArgvWCreateFileMappingWGetExitCodeProcessGetFileAttributesWLookupAccountNameWRFS specific errorSetFile" ascii
		$s17 = "mstartbad sequence numberdevice not a streamdirectory not emptydisk quota exceededdodeltimer: wrong Pfile already closedfile alr" ascii
		$s18 = "structure needs cleaning bytes failed with errno= to unused region of spanGODEBUG: can not enable \"GetQueuedCompletionStatus_cg" ascii
		$s19 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii
		$s20 = "tProcessIdGetSystemDirectoryWGetTokenInformationWaitForSingleObjectadjusttimers: bad pbad file descriptorbad notifyList sizebad " ascii

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and 1 of ($x*) and 12 of them
}
