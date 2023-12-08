import "pe"

rule UPXv103v104Modified
{
	meta:
		author = "malware-lu"
		description = "Detects modified UPX v1.03-v1.04 packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }

	condition:
		$a0 at pe.entry_point
}
