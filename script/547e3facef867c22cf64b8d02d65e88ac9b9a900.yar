rule Multi_Ransomware_BlackCat_e066d802
{
	meta:
		author = "Elastic Security"
		id = "e066d802-b803-4e35-9b53-ae1823662483"
		fingerprint = "05037af3395b682d1831443757376064c873815ac4b6d1c09116715570f51f5d"
		creation_date = "2023-07-27"
		last_modified = "2023-09-20"
		threat_name = "Multi.Ransomware.BlackCat"
		reference_sample = "00360830bf5886288f23784b8df82804bf6f22258e410740db481df8a7701525"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"
		description = "Detects the presence of Multi.Ransomware.BlackCat"
		filetype = "script"

	strings:
		$a1 = "esxcli vm process kill --type=force --world-id=Killing"
		$a2 = "vim-cmd vmsvc/snapshot.removeall $i"
		$a3 = "File already has encrypted extension"

	condition:
		2 of them
}
