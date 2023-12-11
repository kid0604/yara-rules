rule INDICATOR_TOOL_REC_ADFind
{
	meta:
		author = "ditekSHen"
		description = "Detect ADFind"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\AdFind\\AdFind\\AdFind.h" ascii
		$s2 = "\\AdFind\\AdFind\\AdFind.cpp" ascii
		$s3 = "\\AdFind\\Release\\AdFind.pdb" ascii
		$s4 = "joeware_default_adfind.cf" ascii

	condition:
		uint16(0)==0x5a4d and 2 of them
}
