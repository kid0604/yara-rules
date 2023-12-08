rule pos_malware_project_hook
{
	meta:
		author = "@patrickrolsen"
		maltype = "Project Hook"
		version = "0.1"
		description = "Table 1 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
		reference = "759154d20849a25315c4970fe37eac59"
		date = "12/30/2013"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "CallImage.exe"
		$s2 = "BurpSwim"
		$s3 = "Work\\Project\\Load"
		$s4 = "WortHisnal"

	condition:
		uint16(0)==0x5A4D and all of ($s*)
}
