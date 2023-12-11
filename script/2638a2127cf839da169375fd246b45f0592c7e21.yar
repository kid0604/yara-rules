rule INDICATOR_XML_Squiblydoo_1
{
	meta:
		description = "detects Squiblydoo variants extracted from exploit RTF documents."
		author = "ditekSHen"
		os = "windows"
		filetype = "script"

	strings:
		$slt = "<scriptlet" ascii
		$ws1 = "CreateObject(\"WScript\" & \".Shell\")" ascii
		$ws2 = "CreateObject(\"WScript.Shell\")" ascii
		$ws3 = "ActivexObject(\"WScript.Shell\")" ascii
		$r1 = "[\"run\"]" nocase ascii
		$r2 = ".run \"cmd" nocase ascii
		$r3 = ".run chr(" nocase ascii

	condition:
		( uint32(0)==0x4d583f3c or uint32(0)==0x6d783f3c) and $slt and 1 of ($ws*) and 1 of ($r*)
}
