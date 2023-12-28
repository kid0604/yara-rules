rule tick_ABK_downloader_susp_ua
{
	meta:
		description = "ABK downloader malware"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "ade2a4c4fc0bd291d2ecb2f6310c75243107301f445a947409b38777ff014972"
		hash2 = "32dbfc069a6871b2f6cc54484c86b21e2f13956e3666d08077afa97d410185d2"
		hash3 = "d1307937bd2397d92bb200b29eeaace562b10474ff19f0013335e37a80265be6"
		os = "windows"
		filetype = "executable"

	strings:
		$UA = "Mozilla/4.0(compatible;MSIE8.0;WindowsNT6.0;Trident/4.0)"

	condition:
		( uint16(0)==0x5A4D) and ( filesize <50MB) and $UA
}
