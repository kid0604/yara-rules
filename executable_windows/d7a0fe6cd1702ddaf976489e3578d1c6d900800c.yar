import "pe"

rule AdysGlue110
{
	meta:
		author = "malware-lu"
		description = "Detects AdysGlue110 malware by checking for specific byte sequence at the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 2E [4] 0E 1F BF [2] 33 DB 33 C0 AC }

	condition:
		$a0 at pe.entry_point
}
