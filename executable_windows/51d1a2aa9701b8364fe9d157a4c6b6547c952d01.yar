import "pe"

rule Greenbug_Malware_3
{
	meta:
		description = "Detects Backdoor from Greenbug Incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/urp4CD"
		date = "2017-01-25"
		super_rule = 1
		hash1 = "44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49"
		hash2 = "7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "F:\\Projects\\Bot\\Bot\\Release\\Ism.pdb" fullword ascii
		$x2 = "C:\\ddd\\wer2.txt" fullword wide
		$x3 = "\\Microsoft\\Windows\\tmp43hh11.txt" wide

	condition:
		1 of them
}
