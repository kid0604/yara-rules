import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_RawPaste_URL
{
	meta:
		author = "ditekSHen"
		description = "Detects executables (downlaoders) containing URLs to raw contents of a paste"
		os = "windows"
		filetype = "executable"

	strings:
		$u1 = "https://pastebin.com/" ascii wide nocase
		$u2 = "https://paste.ee/" ascii wide nocase
		$u3 = "https://pastecode.xyz/" ascii wide nocase
		$u4 = "https://rentry.co/" ascii wide nocase
		$u5 = "https://paste.nrecom.net/" ascii wide nocase
		$u6 = "https://hastebin.com/" ascii wide nocase
		$u7 = "https://privatebin.info/" ascii wide nocase
		$u8 = "https://penyacom.org/" ascii wide nocase
		$u9 = "https://controlc.com/" ascii wide nocase
		$u10 = "https://tiny-paste.com/" ascii wide nocase
		$u11 = "https://paste.teknik.io/" ascii wide nocase
		$u12 = "https://privnote.com/" ascii wide nocase
		$u13 = "https://hushnote.herokuapp.com/" ascii wide nocase
		$s1 = "/raw/" ascii wide

	condition:
		uint16(0)==0x5a4d and (1 of ($u*) and all of ($s*))
}
