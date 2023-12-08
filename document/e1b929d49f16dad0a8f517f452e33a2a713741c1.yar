import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_NTLM_Exfiltration_IPPattern
{
	meta:
		author = "ditekSHen"
		description = "Detects NTLM hashes exfiltration patterns in command line and various file types"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = /net\suse\s\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
		$s2 = /\/F\s\(\\\\\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
		$s3 = /URL=file:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
		$s4 = /IconFile=\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
		$s5 = /Target=\x22:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
		$s6 = /\/\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
		$s7 = /\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@SSL@\d+\\DavWWWRoot/ ascii wide
		$mso1 = "word/" ascii
		$mso2 = "ppt/" ascii
		$mso3 = "xl/" ascii
		$mso4 = "[Content_Types].xml" ascii

	condition:
		(( uint32(0)==0x46445025 or ( uint16(0)==0x004c and uint32(4)==0x00021401) or uint32(0)==0x00010000 or ( uint16(0)==0x4b50 and 1 of ($mso*))) and 1 of ($s*)) or 1 of ($s*)
}
