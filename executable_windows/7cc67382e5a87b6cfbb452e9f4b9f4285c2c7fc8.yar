import "pe"

rule MALWARE_Win_Matiex
{
	meta:
		author = "ditekSHen"
		description = "Matiex/XetimaLogger keylogger payload"
		clamav_sig = "MALWARE.Win.Trojan.MatiexKeylogger"
		os = "windows"
		filetype = "executable"

	strings:
		$id = "--M-A-T-I-E-X--K-E-Y-L-O-G-E-R--" ascii wide
		$s1 = "StartKeylogger" fullword ascii
		$s2 = "_KeyboardLoggerTimer" ascii
		$s3 = "_ScreenshotLoggerTimer" ascii
		$s4 = "_VoiceRecordLogger" ascii
		$s5 = "_ClipboardLoggerTimer" ascii
		$s6 = "get_logins" fullword ascii
		$s7 = "get_processhackerFucked" fullword ascii
		$s8 = "_ThePSWDSenders" fullword ascii
		$pdb = "\\Before FprmT\\Document VB project\\FireFox Stub\\FireFox Stub\\obj\\Debug\\VNXT.pdb" ascii

	condition:
		uint16(0)==0x5a4d and ($id or 4 of ($s*) or ($pdb and 2 of them ))
}
