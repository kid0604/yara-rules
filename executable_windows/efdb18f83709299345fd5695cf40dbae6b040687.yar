import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CleanMgr
{
	meta:
		description = "detects Windows exceutables potentially bypassing UAC using cleanmgr.exe"
		author = "ditekSHen"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Enviroment\\windir" ascii wide nocase
		$s2 = "\\system32\\cleanmgr.exe" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and all of them
}
