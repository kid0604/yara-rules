rule INDICATOR_TOOL_PWS_LaZagne
{
	meta:
		author = "ditekSHen"
		description = "Detects LaZagne post-exploitation password stealing tool. It is typically embedded with malware in the binary resources."
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "blaZagne.exe.manifest" fullword ascii
		$S2 = "opyi-windows-manifest-filename laZagne.exe.manifest" fullword ascii
		$s3 = "lazagne.softwares.windows." ascii
		$s4 = "lazagne.softwares.sysadmin." ascii
		$s5 = "lazagne.softwares.php." ascii
		$s6 = "lazagne.softwares.memory." ascii
		$s7 = "lazagne.softwares.databases." ascii
		$s8 = "lazagne.softwares.browsers." ascii
		$s9 = "lazagne.config.write_output(" fullword ascii
		$s10 = "lazagne.config." ascii

	condition:
		uint16(0)==0x5a4d and any of them
}
