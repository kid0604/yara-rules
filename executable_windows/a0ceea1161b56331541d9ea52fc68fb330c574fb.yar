rule APT_NK_AR18_165A_HiddenCobra_import_deob
{
	meta:
		author = "NCCIC trusted 3rd party - Edit: Tobias Michalski"
		incident = "10135536"
		date = "2018-04-12"
		category = "hidden_cobra"
		family = "TYPEFRAME"
		md5 = "ae769e62fef4a1709c12c9046301aa5d"
		md5 = "e48fe20eblf5a5887f2ac631fed9ed63"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		description = "Hidden Cobra - Detects installed proxy module as a service"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 8a 01 3c 62 7c 0a 3c 79 7f 06 b2 db 2a d0 88 11 8a 41 01 41 84 c0 75 e8}
		$ = { 8A 08 80 F9 62 7C 0B 80 F9 79 7F 06 82 DB 2A D1 88 10 8A 48 01 40 84 C9 75 E6}

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and any of them
}
