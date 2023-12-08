import "math"
import "pe"

rule VenomRule1
{
	meta:
		description = "Detect the risk of Malware Venom Rule 1"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii
		$x2 = "CertEnumCertificatesInStoreEaster Island Standard TimeG waiting list is corruptedStartServiceCtrlDispatcherW[-]Can not find targ" ascii
		$x3 = " to unallocated span%%!%c(*big.Float=%s)37252902984619140625: leftover defer sp=Arabic Standard TimeAzores Standard TimeCertOpen" ascii
		$x4 = "127.0.0.1:%d152587890625762939453125Bidi_ControlCreateEventWGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempP" ascii
		$x5 = "ssh: unmarshal error for field %s of type %s%sstopTheWorld: not stopped (status != _Pgcstop)x509: invalid elliptic curve private" ascii
		$x6 = " > (den<<shift)/2syntax error scanning numberx509: unknown elliptic curve45474735088646411895751953125Central America Standard T" ascii
		$x7 = "ssh: channel response message received on inbound channelsync: WaitGroup misuse: Add called concurrently with Waitx509: failed t" ascii
		$x8 = " of unexported method previous allocCount=%s flag redefined: %s186264514923095703125931322574615478515625AdjustTokenPrivilegesAl" ascii
		$x9 = "unknown network workbuf is empty initialHeapLive= spinningthreads=%%!%c(big.Int=%s)0123456789ABCDEFX0123456789abcdefx06010215040" ascii
		$x10 = "unixpacketunknown pcws2_32.dll  of size   (targetpc= gcwaiting= gp.status= heap_live= idleprocs= in status  m->mcache= mallocing" ascii
		$x11 = "Variation_Selector[-]Read file error[-]Separator errorbad manualFreeListbufio: buffer fullconnection refusedcontext.Backgroundec" ascii
		$x12 = "Pakistan Standard TimeParaguay Standard TimeSakhalin Standard TimeTasmania Standard TimeWaitForMultipleObjects[+]Remote connecti" ascii
		$x13 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninginvalid runtime symbol tablelarge span treap" ascii
		$x14 = " lockedg= lockedm= m->curg= method:  ms cpu,  not in [ runtime= s.limit= s.state= threads= u_a/u_g= wbuf1.n= wbuf2.n=%!(EXTRA (M" ascii
		$x15 = "bytes.Buffer: reader returned negative count from Readfmt: scanning called UnreadRune with no rune availablegcControllerState.fi" ascii
		$x16 = "et nodeaddress not a stack addressadministratively prohibitedc:\\windows\\system32\\cmd.exechannel number out of rangecommunicat" ascii
		$x17 = "tifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availablenon-minimal lengthoperat" ascii
		$x18 = "invalid network interface nameinvalid pointer found on stacknode is not its parent's childnotetsleep - waitm out of syncprotocol" ascii
		$x19 = "bad flushGen bad map statechannelEOFMsgdalTLDpSugct?disconnectMsgempty integerexchange fullfatal error: gethostbynamegetservbyna" ascii
		$x20 = "structure needs cleaningunexpected exponent baseunexpected mantissa baseunknown channel type: %v bytes failed with errno= to unu" ascii

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and 3 of ($x*)
}
