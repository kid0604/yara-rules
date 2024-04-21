rule case_15184_FilesToHash_17jun
{
	meta:
		description = "15184_ - file 17jun.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/"
		date = "2022-11-28"
		hash1 = "41e230134deca492704401ddf556ee2198ef6f32b868ec626d9aefbf268ab6b1"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii
		$x2 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125ERROR: unable to download agent fromGo pointer stored in" ascii
		$x3 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
		$x4 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
		$x5 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dchacha20: wrong HChaCha20 " ascii
		$x6 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
		$x7 = "tls: certificate used with invalid signature algorithmtls: server resumed a session with a different versionx509: cannot verify " ascii
		$x8 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionreflect mismatchremote I/O errorruntime:  g:  g=" ascii
		$x9 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii
		$x10 = "unixpacketunknown pcuser-agentws2_32.dll  of size   (targetpc= ErrCode=%v KiB work,  freeindex= gcwaiting= idleprocs= in status " ascii
		$x11 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONContent TypeContent-TypeCookie.ValueECDSA-SHA256ECDSA-SH" ascii
		$x12 = "entersyscallexit status gcBitsArenasgcpacertracegetaddrinfowhost is downhttp2debug=1http2debug=2illegal seekinvalid baseinvalid " ascii
		$x13 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8unexpected buffer len=%vx509: malformed validityzlib: in" ascii
		$x14 = "IP addressInstaller:Keep-AliveKharoshthiLockFileExManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCO" ascii
		$x15 = " to non-Go memory , locked to thread298023223876953125: day out of rangeArab Standard TimeCaucasian_AlbanianCommandLineToArgvWCr" ascii
		$x16 = "= flushGen  for type  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= stream=%d sweepgen  sweepgen= target" ascii
		$x17 = "(unknown), newval=, oldval=, plugin:, size = , tail = --site-id244140625: status=AuthorityBassa_VahBhaiksukiClassINETCuneiformDi" ascii
		$x18 = " is unavailable()<>@,;:\\\"/[]?=,M3.2.0,M11.1.00601021504Z0700476837158203125: cannot parse <invalid Value>ASCII_Hex_DigitAccept" ascii
		$x19 = "span set block with unpopped elements found in resettls: received a session ticket with invalid lifetimetls: server selected uns" ascii
		$x20 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackcertificate unobtainablechacha20" ascii

	condition:
		uint16(0)==0x5a4d and filesize <14000KB and 1 of ($x*)
}
