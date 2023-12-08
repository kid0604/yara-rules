import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_Discord_Regex
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing Discord tokens regular expressions"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_\\-]{27}|mfa\\.[a-zA-Z0-9_\\-]{84}" ascii wide nocase

	condition:
		( uint16(0)==0x5a4d and all of them ) or all of them
}
