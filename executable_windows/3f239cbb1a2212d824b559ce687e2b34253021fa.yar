rule tick_ABK_downloader
{
	meta:
		description = "ABK downloader malware"
		author = "JPCERT/CC Incident Response Group"
		hash = "5ae244a012951ab2089ad7dc70e564f90586c78ff08b93bb2861bb69edcdd5c5"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "PccNT.exe" wide
		$bytecode = {	50 63 63 00 4e 54 2e 00 65 78 65 00 }

	condition:
		( uint16(0)==0x5A4D) and ( filesize >10MB) and (( any of ($a1)) or $bytecode)
}
