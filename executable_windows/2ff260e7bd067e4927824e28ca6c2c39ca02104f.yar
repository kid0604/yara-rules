rule APT_HiddenCobra_import_obfuscation_2
{
	meta:
		author = "NCCIC trusted 3rd party - Edit: Tobias Michalski"
		incident = "10135536"
		date = "2018-04-12"
		category = "hidden_cobra"
		family = "TYPEFRAME"
		hash0 = "bfb41bc0c3856aa0a81a5256b7b8da51"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		description = "Hidden Cobra - Detects remote access trojan"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = {A6 D6 02 EB 4E B2 41 EB C3 EF 1F}
		$s1 = {B6 DF 01 FD 48 B5 }
		$s2 = {B6 D5 0E F3 4E B5 }
		$s3 = {B7 DF 0E EE }
		$s4 = {B6 DF 03 FC }
		$s5 = {A7 D3 03 FC }

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and all of them
}
