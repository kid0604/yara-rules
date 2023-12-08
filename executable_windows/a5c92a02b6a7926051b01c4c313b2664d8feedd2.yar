import "pe"

rule INDICATOR_MSI_EXE2MSI
{
	meta:
		author = "ditekSHen"
		description = "Detects executables converted to .MSI packages using a free online converter."
		snort2_sid = "930061-930063"
		snort3_sid = "930022"
		os = "windows"
		filetype = "executable"

	strings:
		$winin = "Windows Installer" ascii
		$title = "Exe to msi converter free" ascii

	condition:
		uint32(0)==0xe011cfd0 and ($winin and $title)
}
