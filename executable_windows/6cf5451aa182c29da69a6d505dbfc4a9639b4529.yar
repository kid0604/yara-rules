import "pe"

rule NXPEPackerv10
{
	meta:
		author = "malware-lu"
		description = "Detects NXPE Packer v1.0"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FF 60 FF CA FF 00 BA DC 0D E0 40 00 50 00 60 00 70 00 80 00 }

	condition:
		$a0 at pe.entry_point
}
