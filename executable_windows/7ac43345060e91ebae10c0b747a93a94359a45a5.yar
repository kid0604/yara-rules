import "pe"

rule MAL_EXE_RoyalRansomware
{
	meta:
		author = "Silas Cutler, modfied by Florian Roth"
		description = "Detection for Royal Ransomware seen Dec 2022"
		date = "2023-01-03"
		version = "1.0"
		hash = "a8384c9e3689eb72fa737b570dbb53b2c3d103c62d46747a96e1e1becf14dfea"
		DaysofYARA = "3/100"
		os = "windows"
		filetype = "executable"

	strings:
		$x_ext = ".royal_" wide
		$x_fname = "royal_dll.dll"
		$s_readme = "README.TXT" wide
		$s_cli_flag01 = "-networkonly" wide
		$s_cli_flag02 = "-localonly" wide
		$x_ransom_msg01 = "If you are reading this, it means that your system were hit by Royal ransomware."
		$x_ransom_msg02 = "Try Royal today and enter the new era of data security!"
		$x_onion_site = "http://royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion/"

	condition:
		uint16(0)==0x5A4D and (2 of ($x*) or 5 of them )
}
