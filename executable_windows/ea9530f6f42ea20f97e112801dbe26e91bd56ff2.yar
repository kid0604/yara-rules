rule SpyNet : malware
{
	meta:
		description = "Ruleset to detect SpyNetV2 samples. "
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "odNotice.txt"
		$b = "camera This device has camera!"
		$c = "camera This device has Nooo camera!"
		$d = "send|1sBdBBbbBBF|K|"
		$e = "send|372|ScreamSMS|senssd"
		$f = "send|5ms5gs5annc"
		$g = "send|45CLCLCa01"
		$h = "send|999SAnd|TimeStart"
		$i = "!s!c!r!e!a!m!"

	condition:
		4 of them
}
