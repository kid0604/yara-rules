import "pe"

rule HKTL_DomainPasswordSpray
{
	meta:
		description = "Detects the Powershell password spray tool DomainPasswordSpray"
		author = "Arnim Rupp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://github.com/dafthack/DomainPasswordSpray"
		date = "2023-01-13"
		score = 60
		hash1 = "44d4c0ae5673d2a076f3b5acdc83063aca49d58e6dd7cf73d0b927f83d359247"
		os = "windows"
		filetype = "script"

	strings:
		$s = "Invoke-DomainPasswordSpray" fullword ascii wide

	condition:
		filesize <100KB and all of them
}
