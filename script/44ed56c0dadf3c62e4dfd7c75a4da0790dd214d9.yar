import "pe"

rule ME_Campaign_Malware_3
{
	meta:
		description = "Detects malware from Middle Eastern campaign reported by Talos"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
		date = "2018-02-07"
		hash1 = "15f5aaa71bfa3d62fd558a3e88dd5ba26f7638bf2ac653b8d6b8d54dc7e5926b"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "objWShell.Run \"powershell.exe -ExecutionPolicy Bypass -File \"\"%appdata%\"\"\\sys.ps1\", 0 " fullword ascii
		$x2 = "objFile.WriteLine \"New-Item -Path \"\"$ENV:APPDATA\\Microsoft\\Templates\"\" -ItemType Directory -Force }\" " fullword ascii
		$x3 = "objFile.WriteLine \"$path = \"\"$ENV:APPDATA\\Microsoft\\Templates\\Report.doc\"\"\" " fullword ascii
		$s4 = "File=appData & \"\\sys.ps1\"" fullword ascii

	condition:
		uint16(0)==0x6553 and filesize <400KB and 1 of them
}
