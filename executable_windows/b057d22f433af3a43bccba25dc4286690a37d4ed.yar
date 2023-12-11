import "pe"

rule MALWARE_Win_DarkVNC
{
	meta:
		author = "ditekSHen"
		description = "Detects DarkVNC"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "USR-%s(%s)_%S-%S%u%u" fullword wide
		$s2 = "BOT-%s(%s)_%S-%S%u%u" fullword wide
		$s3 = "USR-UnicodeErr(Err)_%s-%s%u%u" fullword ascii
		$s4 = "BOT-UnicodeErr(Err)_%s-%s%u%u" fullword ascii
		$s5 = "PRM_STRG" fullword wide
		$s6 = "bot_shell >" ascii
		$s7 = "monitor_off / monitor_on" ascii
		$s8 = "kbd_off / kbd_on" ascii
		$s9 = "ActiveDll: Dll inject thread for process 0x%x terminated with status: %u" ascii
		$s10 = "PsSup: File %s successfully started with parameter \"%s\"" ascii
		$s11 = "PsSup: ShellExecute failed. File: %s, error %u" ascii
		$s12 = "#hvnc" fullword ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
