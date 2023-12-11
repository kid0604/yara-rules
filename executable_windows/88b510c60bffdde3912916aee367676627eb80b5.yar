rule Unspecified_Malware_Jul17_2C
{
	meta:
		description = "Unspecified Malware - CN relation"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/CX3KaY"
		date = "2017-07-18"
		hash1 = "e8156ec1706716cada6f57b6b8ccc9fb0eb5debe906ac45bdc2b26099695b8f5"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%AllUsersProfile%\\DeviceSync\\m.exe" fullword wide
		$x2 = "freenow.chickenkiller.com" fullword ascii
		$x3 = "\\Release\\PhantomNet-SSL.pdb" ascii
		$s1 = "SELECT * FROM AntiVirusProduct" fullword ascii
		$s2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%08X-%04X-%04X-%02X%02X%02X%02X" fullword ascii
		$s3 = "Proxy-Authenticate: Basic" fullword ascii
		$s4 = "Proxy-Authenticate: NTLM" fullword ascii
		$s5 = "Root\\SecurityCenter2" fullword wide
		$s6 = "aaabbbcccddd" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and (1 of ($x*) or 4 of ($s*))) or ( all of them )
}
