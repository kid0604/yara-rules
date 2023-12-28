rule malware_sqroot_lnk
{
	meta:
		description = "sqroot drop lnk file using unknown actors"
		author = "JPCERT/CC Incident Response Group"
		hash = "16ac092af64bbab7dbaef60cd796e47c5d2a6fec6164906c1fbd0c9c51861936"
		os = "windows"
		filetype = "executable"

	strings:
		$command1 = "bwBuACAAZQByAHIAbwByACAAcgBlAHMA" wide
		$command2 = "%temp%\\ex.lnk" wide nocase
		$command3 = "%temp%\\f.vbs" wide nocase
		$command4 = "%temp%\\b64.txt" wide nocase
		$command5 = "%temp%\\i.log" wide nocase
		$command6 = "%temp%\\result.vbs" wide nocase
		$command7 = ".position = .size-12" wide
		$command8 = "AscW(.read(2))=^&" wide

	condition:
		uint16(0)==0x004c and filesize >1MB and 4 of ($command*)
}
