import "pe"

rule SUSP_PS1_Combo_TransferSH_Feb24 : SCRIPT
{
	meta:
		description = "Detects suspicious PowerShell command that downloads content from transfer.sh as often found in loaders"
		author = "Florian Roth"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		date = "2024-02-23"
		score = 70
		os = "windows"
		filetype = "script"

	strings:
		$x1 = ".DownloadString('https://transfer.sh"
		$x2 = ".DownloadString(\"https://transfer.sh"
		$x3 = "Invoke-WebRequest -Uri 'https://transfer.sh"
		$x4 = "Invoke-WebRequest -Uri \"https://transfer.sh"

	condition:
		1 of them
}
