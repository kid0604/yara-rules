import "pe"

rule vfpexeNcV500WangJianGuo
{
	meta:
		author = "malware-lu"
		description = "Detects VFP executable files with specific byte pattern at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D [12] 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }

	condition:
		$a0 at pe.entry_point
}
