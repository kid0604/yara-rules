rule INDICATOR_TOOL_ENC_DiskCryptor
{
	meta:
		author = "ditekSHen"
		description = "Detect DiskCryptor open encryption solution that offers encryption of all disk partitions"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\DiskCryptor\\DCrypt\\" ascii
		$s1 = "Error getting %sbootloader configuration" fullword wide
		$s2 = "loader.iso" fullword wide
		$s3 = "Bootloader config for [%s]" fullword wide
		$s4 = "dc_get_mbr_config" fullword ascii
		$s5 = "dc_encrypt_iso_image" fullword ascii
		$s6 = "dc_start_re_encrypt" fullword ascii
		$s7 = "dc_start_encrypt" fullword ascii
		$s8 = "_w10_reflect_" ascii
		$d1 = "\\DosDevices\\dcrypt" fullword wide
		$d2 = "$dcsys$_fail_%x" fullword wide
		$d3 = "%s\\$DC_TRIM_%x$" fullword wide
		$d4 = "\\Device\\dcrypt" fullword wide
		$d5 = "%s\\$dcsys$" fullword wide

	condition:
		uint16(0)==0x5a4d and ((1 of ($x*) and 2 of ($s*)) or 4 of ($s*) or 3 of ($d*))
}
