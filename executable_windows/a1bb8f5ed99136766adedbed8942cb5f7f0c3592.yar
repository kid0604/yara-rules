rule FourElementSword_ResN32DLL
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Release\\BypassUAC.pdb" ascii
		$s2 = "\\ResN32.dll" wide
		$s3 = "Eupdate" fullword wide

	condition:
		all of them
}
