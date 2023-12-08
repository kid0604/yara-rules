rule INDICATOR_TOOL_DWAgent_SoundCapture
{
	meta:
		author = "ditekSHen"
		description = "Detect DWAgent Remote Administration Tool Sound Capture Module"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DWASoundCapture" ascii
		$s2 = /_Z\d{2}DWASoundCapture/ ascii
		$s3 = "_Z6recordPvS_" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
