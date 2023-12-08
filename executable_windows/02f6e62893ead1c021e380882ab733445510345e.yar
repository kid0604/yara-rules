rule PassCV_Sabre_Malware_Excalibur_1
{
	meta:
		description = "PassCV Malware mentioned in Cylance Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
		date = "2016-10-20"
		hash1 = "21566f5ff7d46cc9256dae8bc7e4c57f2b9261f95f6ad2ac921558582ea50dfb"
		hash2 = "02922c5d994e81629d650be2a00507ec5ca221a501fe3827b5ed03b4d9f4fb70"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "F:\\Excalibur\\Excalibur\\" ascii
		$x2 = "Excalibur\\bin\\Shell.pdb" ascii
		$x3 = "SaberSvc.exe" wide
		$s1 = "BBB.exe" fullword wide
		$s2 = "AAA.exe" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 1 of ($x*) or all of ($s*)) or 3 of them
}
