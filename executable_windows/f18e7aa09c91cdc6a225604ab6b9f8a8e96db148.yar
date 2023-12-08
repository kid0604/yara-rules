rule APT34_Malware_Exeruner
{
	meta:
		description = "Detects APT 34 malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
		date = "2017-12-07"
		hash1 = "c75c85acf0e0092d688a605778425ba4cb2a57878925eee3dc0f4dd8d636a27a"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\obj\\Debug\\exeruner.pdb" ascii
		$x2 = "\"wscript.shell`\")`nShell0.run" wide
		$x3 = "powershell.exe -exec bypass -enc \" + ${global:$http_ag} +" wide
		$x4 = "/c powershell -exec bypass -window hidden -nologo -command " fullword wide
		$x5 = "\\UpdateTasks\\JavaUpdatesTasksHosts\\" wide
		$x6 = "schtasks /create /F /ru SYSTEM /sc minute /mo 1 /tn" wide
		$x7 = "UpdateChecker.ps1 & ping 127.0.0.1" wide
		$s8 = "exeruner.exe" fullword wide
		$s9 = "${global:$address1} = $env:ProgramData + \"\\Windows\\Microsoft\\java\";" fullword wide
		$s10 = "C:\\ProgramData\\Windows\\Microsoft\\java" fullword wide
		$s11 = "function runByVBS" fullword wide
		$s12 = "$84e31856-683b-41c0-81dd-a02d8b795026" fullword ascii
		$s13 = "${global:$dns_ag} = \"aQBmACAAKAAoAEcAZQB0AC0AVwBtAGk" wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 1 of them
}
