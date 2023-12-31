import "pe"

rule urausy_skype_dat : memory
{
	meta:
		author = "AlienVault Labs"
		description = "Yara rule to match against memory of processes infected by Urausy skype.dat"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "skype.dat" ascii wide
		$b = "skype.ini" ascii wide
		$win1 = "CreateWindow"
		$win2 = "YIWEFHIWQ" ascii wide
		$desk1 = "CreateDesktop"
		$desk2 = "MyDesktop" ascii wide

	condition:
		$a and $b and ( all of ($win*) or all of ($desk*))
}
