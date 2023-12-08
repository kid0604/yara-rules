import "math"
import "pe"

rule NPSRule1
{
	meta:
		description = "Detect the risk of Malware NPS Rule 1"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
		$x2 = "FilledVerySmallSquare;Georgian Standard TimeGetControllerAndActionGetEnvironmentStringsWGetTimeZoneInformationHawaiian Standard " ascii
		$x3 = "lock: lock countservice %s already existsservice function disabledslice bounds out of rangesnappy: unsupported inputsocket type " ascii
		$x4 = "tag handle must contain alphanumerical characters onlytarget must be an absolute URL or an absolute path: %qtls: certificate use" ascii
		$x5 = "%sidentifier on left side of :=ilnpv6 locator update messageinteger not minimally-encodedinternal error: took too muchinvalid bl" ascii
		$x6 = "flate: internal error: function %q not definedgarbage collection scangcDrain phase incorrecthealth_check_max_failedhtml/template" ascii
		$x7 = "Subject: AMDisbetter!AVX512BITALGAuthenticAMDBeegoVersionBidi_ControlCIDR addressCONTENT_TYPECONTINUATIONCentaurHaulsCircleMinus" ascii
		$x8 = "sender tried to send more than declared Content-Length of %d bytestls: certificate private key (%T) does not implement crypto.Si" ascii
		$x9 = "debugPtrmask.lockdecryption faileddeprecated formatdiscarded samplesdownharpoonright;entersyscallblockexec format errorexec: not" ascii
		$x10 = "%s %s:%d s=%d, gp->status=, not pointer,\"filename\":\"-byte block (/([^.]+).(.+)/debug/pprof//etc/rc.d/K02/etc/rc.d/S9038146972" ascii
		$x11 = "%s.%s.ka.acme.invalid(?m)^\\[[^\\[\\]\\r\\n]+\\](SpinLock::)?Unlock.*, levelBits[level] = 18626451492309570312593132257461547851" ascii
		$x12 = "    beego.GlobalControllerRouter[\"acme/autocert: no token cert for %qacme: certificate chain is too deepacme: certificate chain" ascii
		$x13 = "%s \"%s\"__restoreandslope;angmsdaa;angmsdab;angmsdac;angmsdad;angmsdae;angmsdaf;angmsdag;angmsdah;angrtvbd;approxeq;assets_jsat" ascii
		$x14 = "WriteHeader called after Handler finishedapplication/vndnokiaconfiguration-messageasn1: internal error in parseTagAndLengthbinar" ascii
		$x15 = "Stack traces of holders of contended mutexesapplication/x-bytecodeelisp=(compiled=elisp)cipher: NewGCM requires 128-bit block ci" ascii
		$x16 = "%s.%s.acme.invalid(Mutex::)?Unlock.*, locked to thread/debug/pprof/trace1 or 2 expressions114.114.114.114:5329802322387695312540" ascii
		$x17 = "runtime: typeBitsBulkBarrier without typeseconds and debug params are incompatiblesetCheckmarked and isCheckmarked disagreestart" ascii
		$x18 = "UnsubscribeServiceChangeNotifications_cgo_notify_runtime_init_done missingacme/autocert: Manager.Prompt not setacme/autocert: ce" ascii
		$x19 = "MapIter.Value called before NextMultiple ,inline maps in struct NtWow64QueryInformationProcess64SYSTEM\\CurrentControlSet\\Contr" ascii
		$x20 = "            Method: \"bufio.Scanner: SplitFunc returns advance count beyond inputcannot create Encoder with more than 256 data+p" ascii

	condition:
		uint16(0)==0x5a4d and filesize <36000KB and 3 of ($x*)
}
