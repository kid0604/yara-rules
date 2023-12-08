rule INDICATOR_TOOL_PPLBLade
{
	meta:
		author = "ditekSHen"
		description = "Detects PPLBlade Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "PPLBlade" ascii
		$x2 = "/PPLBlade/" ascii
		$x3 = "PPLBlade.exe --mode" ascii
		$x4 = "PPLBLADE.SYSPPLBlade.dmp" ascii
		$s1 = "Dump bytes sent at %s:%d. Protocol: %s" ascii
		$s2 = "Deobfuscated dump saved in file %s" ascii
		$m1 = "main.WriteDriverOnDisk" ascii
		$m2 = "main.ProcExpOpenProc" ascii
		$m3 = "main.miniDumpCallback" ascii
		$m4 = "main.copyDumpBytes" ascii
		$m5 = "main.MiniDumpGetBytes" ascii
		$m6 = "main.SendBytesRaw" ascii
		$m7 = "main.SendBytesSMB" ascii
		$m8 = "main.DeobfuscateDump" ascii
		$m9 = "main.dumpMutex" ascii
		$m10 = "main.dbghelpDLL" ascii
		$m11 = "main.miniDumpWriteDump" ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($x*) or (1 of ($x*) and (1 of ($s*) or 3 of ($m*))) or ( all of ($s*) and 3 of ($m*)) or (7 of ($m*)))
}
