import "pe"

rule MAL_BR_Report_TheDao
{
	meta:
		description = "Detects indicator in malicious UPX packed samples"
		author = "@br_data repo"
		reference = "https://github.com/br-data/2019-winnti-analyse"
		date = "2019-07-24"
		os = "windows"
		filetype = "executable"

	strings:
		$b = { DA A0 }

	condition:
		uint16(0)==0x5a4d and $b at pe.overlay.offset and pe.overlay.size>100
}
