import "pe"

rule INDICATOR_TOOL_Havoc
{
	meta:
		author = "ditekSHen"
		description = "Detects Havoc Demon"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "X-Havoc:" wide
		$x2 = "X-Havoc-Agent:" wide
		$s1 = "\\Werfault.exe" wide
		$s2 = "/funny_cat.gif" wide

	condition:
		uint16(0)==0x5a4d and ( all of ($x*) or 3 of them or (pe.number_of_imports==0 and pe.number_of_exports==0 and 2 of them ))
}
