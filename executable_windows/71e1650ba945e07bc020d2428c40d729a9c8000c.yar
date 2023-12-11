rule Windows_Ransomware_Egregor_f24023f3 : beta
{
	meta:
		author = "Elastic Security"
		id = "f24023f3-c887-42fc-8927-cdbd04b5f84f"
		fingerprint = "3a82a548658e0823678ec9d633774018ddc6588f5e2fbce74826a46ce9c43c40"
		creation_date = "2020-10-15"
		last_modified = "2021-08-23"
		description = "Identifies EGREGOR (Sekhemt) ransomware"
		threat_name = "Windows.Ransomware.Egregor"
		reference = "https://www.bankinfosecurity.com/egregor-ransomware-adds-to-data-leak-trend-a-15110"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "M:\\sc\\p\\testbuild.pdb" ascii fullword
		$a2 = "C:\\Logmein\\{888-8888-9999}\\Logmein.log" wide fullword
		$a3 = "nIcG`]/h3kpJ0QEAC5OJC|<eT}}\\5K|h\\\\v<=lKfHKO~01=Lo0C03icERjo0J|/+|=P0<UeN|e2F@GpTe]|wpMP`AG+IFVCVbAErvTeBRgUN1vQHNp5FVtc1WVi/G"
		$a4 = "pVrGRgJui@6ejnOu@4KgacOarSh|firCToW1LoF]7BtmQ@2j|hup2owUHQ6W}\\U3gwV6OwSPTMQVq2|G=GKrHpjOqk~`Ba<qu\\2]r0RKkf/HGngsK7LhtvtJiR}+4J"
		$a5 = "Your network was ATTACKED, your computers and servers were LOCKED," ascii wide
		$a6 = "Do not redact this special technical block, we need this to authorize you." ascii wide

	condition:
		2 of ($a*)
}
